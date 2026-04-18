/* =============================================================================
 * NS-3 MQTT IoT Simulation — 1 Broker, 6 Sensors, 1 Attacker + AI DEFENDER
 * =============================================================================
 *
 * TOPOLOGY  (Wireless 802.11b Ad-Hoc, 10.0.0.0/24)
 *
 *   Node  IP           Role
 *   ────  ───────────  ──────────────────────────────────────
 *     0   10.0.0.1     MQTT Broker (TCP:1883)  [TARGET]
 *     1   10.0.0.2     Sensor 1 — Temperature & Humidity  (DHT22)
 *     2   10.0.0.3     Sensor 2 — Water Level             (HC-SR04)
 *     3   10.0.0.4     Sensor 3 — Ultrasonic Distance     (HC-SR04)
 *     4   10.0.0.5     Sensor 4 — Flame / IR Detection    (KY-026)
 *     5   10.0.0.6     Sensor 5 — Motion Detection        (PIR HC-SR501)
 *     6   10.0.0.7     Sensor 6 — Light Intensity         (LDR / BH1750)
 *     7   10.0.0.8     ATTACKER  (DDoS agent)
 *     8   10.0.0.9     AI DEFENDER (CNN-BiLSTM-Attn IDS/IPS)
 *
 * ATTACK MODES :
 *   0 SYN    — rapid TCP SYN flood                  
 *   1 BASIC  — standard MQTT CONNECT flood          
 *   2 DELAY  — slow CONNECT, delay before payload   
 *   3 INVSUB — MQTT SUBSCRIBE with invalid topic    
 *   4 WILL   — MQTT CONNECT with large WILL payload 
 *
 * DEFENDER ACTIONS (mirrors your Python rl_env.py):
 *   0  ALLOW             — pass traffic normally
 *   1  RATE_LIMIT_IP     — throttle connections from source
 *   2  TEMP_BLOCK_IP     — block IP for block-duration window
 *   3  PERM_BLOCK_IP     — permanently drop all traffic from IP
 *   4  DROP_SYN          — silently drop SYN packets
 *   5  DROP_CONNECT      — drop MQTT CONNECT packets
 *   6  DELAY_CONNECT     — queue CONNECT with artificial delay
 *   7  LIMIT_PUBLISH     — cap publish message rate
 *   8  BLOCK_SUBSCRIBE   — reject SUBSCRIBE packets
 *   9  DISCONNECT        — force-close client socket
 *  10  QUARANTINE        — redirect client to shadow broker
 *  11  ISOLATE_NODE      — block all traffic from the node
 *  12  REDUCE_QOS        — downgrade QoS to 0
 *  13  ALERT_ONLY        — log event, no mitigation
 *  14  ESCALATE          — raise threat level
 *  15  DEESCALATE        — lower threat level
 *
 * HOW THE AI DEFENDER WORKS IN THIS SIMULATION:
 *   The AI Defender is modelled as a dedicated ns-3 node (Node 8) that
 *   mirrors all traffic to/from the broker by reading FlowMonitor statistics.
 *   Every g_defEvalInterval seconds the defender:
 *     1. Computes 12 network features (packet rate, byte rate, SYN ratio, etc.)
 *        using the same feature set your CNN-BiLSTM-Attn model was trained on.
 *     2. Writes those features to  defender_query.csv
 *     3. Calls:  python3 <defenderScript> --query defender_query.csv
 *                                          --out    defender_result.json
 *        The Python script loads your saved weights and returns an action ID.
 *     4. Reads defender_result.json and enforces the action:
 *        — rate-limit / block: closes or throttles attacker socket at broker
 *        — alert-only: logs to defender_log.csv
 *        — allow: does nothing
 *
 * OUTPUT → defended_1broker_output/
 *   pcap/                  — wireshark captures
 *   flows.csv              — per-flow FlowMonitor stats
 *   rl_log.csv             — attacker Q-table log
 *   timeseries.csv         — per-second network snapshot
 *   defender_log.csv       — defender action log
 *   summary.csv            — final summary
 *   mqtt-defended-anim.xml — NetAnim animation file
 *   mqtt-defended-flowmonitor.xml
 *
 * BUILD:
 *   cp mqtt_1broker_defended.cc  $NS3_DIR/scratch/
 *   cp defender_ns3_bridge.py    $NS3_DIR/scratch/   (generated below)
 *   cd $NS3_DIR && ./ns3 run scratch/mqtt_1broker_defended
 *
 * WEIGHTS PATH (edit before building):
 *   Update DEFENDER_WEIGHTS_DIR below to match your Downloads folder.
 * =============================================================================
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/wifi-module.h"
#include "ns3/mobility-module.h"
#include "ns3/applications-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/netanim-module.h"
#include "ns3/tcp-socket-factory.h"
#include "ns3/inet-socket-address.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <cmath>
#include <cstdlib>           // system()
#include <sys/stat.h>

using namespace ns3;
NS_LOG_COMPONENT_DEFINE ("MqttDefended1Broker");

// ════════════════════════════════════════════════════════════════════════════
//  USER CONFIGURATION — edit these paths before running
// ════════════════════════════════════════════════════════════════════════════

// Full path to the folder shown in your Downloads terminal screenshot.
// Must contain the six weight files listed in the screenshot.
static std::string DEFENDER_WEIGHTS_DIR = "/home/ja/Downloads";          // ← change if different

// Which detector variant to use: "cnn_only" | "cnn_attn" | "cnn_bilstm_attn"
static std::string ACTIVE_DETECTOR = "cnn_bilstm_attn";

// Path to the Python bridge script (placed alongside this .cc in scratch/)

static std::string DEFENDER_SCRIPT =
    "/home/ja/ns-allinone-3.46.1/ns-3.46.1/scratch/defender_ns3_bridge.py";  // ← set your NS3 path

// ════════════════════════════════════════════════════════════════════════════
//  SIMULATION PARAMETERS
// ════════════════════════════════════════════════════════════════════════════
static const uint16_t MQTT_PORT     = 1883;
static double      g_simTime        = 120.0;   // longer to show defender reacting
static double      g_attackStart    = 15.0;    // attack begins at 15 s
static double      g_evalInterval   = 8.0;     // attacker eval period
static double      g_defEvalInterval= 4.0;     // defender checks every 4 s
static double      g_epsilon        = 0.90;
static uint32_t    g_seed           = 42;
static std::string g_outDir         = "defended_1broker_output";

// ─── Attacker hyperparameters ─────────────────────────────────────────────
static const double EPS_DECAY = 0.98, EPS_FLOOR = 0.05, GAMMA = 0.95, LR = 0.10;
static const int    N_MODES   = 5;

// ════════════════════════════════════════════════════════════════════════════
//  ATTACK PROFILES
// ════════════════════════════════════════════════════════════════════════════
struct AtkProfile { const char *name, *shortName; uint32_t pktBytes; double delta; };
static const AtkProfile ATK[5] = {
  {"SYN_TCP_Flooding",                   "SYN",    62,  1.709},
  {"Basic_Connect_Flooding",             "BASIC",  61,  0.476},
  {"Delayed_Connect_Flooding",           "DELAY",  62,  0.890},
  {"Invalid_Subscription_Flooding",      "INVSUB", 63,  0.751},
  {"Connect_Flooding_with_WILL_payload", "WILL",   162, 0.490}
};

// ════════════════════════════════════════════════════════════════════════════
//  DEFENDER ACTION NAMES (mirrors rl_env.py)
// ════════════════════════════════════════════════════════════════════════════
static const char* DEF_ACTION_NAMES[16] = {
  "ALLOW",           "RATE_LIMIT_IP",   "TEMP_BLOCK_IP",  "PERM_BLOCK_IP",
  "DROP_SYN",        "DROP_CONNECT",    "DELAY_CONNECT",  "LIMIT_PUBLISH",
  "BLOCK_SUBSCRIBE", "DISCONNECT",      "QUARANTINE",     "ISOLATE_NODE",
  "REDUCE_QOS",      "ALERT_ONLY",      "ESCALATE",       "DEESCALATE"
};

// ════════════════════════════════════════════════════════════════════════════
//  GLOBALS
// ════════════════════════════════════════════════════════════════════════════
static Ipv4Address             g_brokerIP, g_attackerIP, g_defenderIP;
static Ptr<FlowMonitor>        g_mon;
static Ptr<Ipv4FlowClassifier> g_cls;
static AnimationInterface*     g_anim = nullptr;

// Defender state
static int    g_defLastAction   = 0;      // last action taken
static bool   g_attackerBlocked = false;  // is attacker currently blocked?
static int    g_defEscLevel     = 0;      // escalation level 0-5
static double g_defLastDetProb  = 0.0;    // last detection probability

// Defender statistics
static uint32_t g_defTP = 0, g_defFP = 0, g_defTN = 0, g_defFN = 0;
static uint32_t g_defActions[16] = {};

// Attacker state (Q-table)
struct RLState {
  int      mode = 0;
  double   q[N_MODES] = {};
  double   eps  = g_epsilon;
  int      steps = 0;
  uint32_t mU[N_MODES] = {};
  Ptr<Application> app;
};
static RLState g_rl;

// Forward declarations
static std::string Out(const std::string& f);
static void MkDir(const std::string& d);

// ════════════════════════════════════════════════════════════════════════════
//  HELPERS
// ════════════════════════════════════════════════════════════════════════════
static std::string Out(const std::string& f){ return g_outDir+"/"+f; }
static void MkDir(const std::string& d){ mkdir(d.c_str(),0755); }

// ════════════════════════════════════════════════════════════════════════════
//  MQTT FRAME BUILDER  (identical to original files)
// ════════════════════════════════════════════════════════════════════════════
namespace Mqtt {
static std::vector<uint8_t> varlen(uint32_t n){
  std::vector<uint8_t> o;
  do{ uint8_t b=n&0x7F; n>>=7; o.push_back(b|(n?0x80:0)); }while(n);
  return o;
}
static std::vector<uint8_t> mstr(const std::string &s){
  std::vector<uint8_t> o;
  o.push_back((s.size()>>8)&0xFF); o.push_back(s.size()&0xFF);
  for(char c:s) o.push_back((uint8_t)c);
  return o;
}
static void app(std::vector<uint8_t>&d,const std::vector<uint8_t>&s){
  d.insert(d.end(),s.begin(),s.end());
}
std::vector<uint8_t> Connect(const std::string &cid,
                              bool will=false,
                              const std::string &wt="",
                              const std::string &wm=""){
  std::vector<uint8_t> vh;
  app(vh,mstr("MQTT")); vh.push_back(0x04);
  vh.push_back(will?0x06:0x02);
  vh.push_back(0x00); vh.push_back(0x3C);
  std::vector<uint8_t> pay; app(pay,mstr(cid));
  if(will){ app(pay,mstr(wt)); app(pay,mstr(wm)); }
  std::vector<uint8_t> rem; app(rem,vh); app(rem,pay);
  std::vector<uint8_t> f; f.push_back(0x10);
  app(f,varlen(rem.size())); app(f,rem); return f;
}
std::vector<uint8_t> ConnAck(uint8_t rc=0x00){ return {0x20,0x02,0x00,rc}; }
std::vector<uint8_t> Publish(const std::string &topic, const std::string &payload){
  std::vector<uint8_t> rem; app(rem,mstr(topic));
  for(char c:payload) rem.push_back((uint8_t)c);
  std::vector<uint8_t> f; f.push_back(0x30);
  app(f,varlen(rem.size())); app(f,rem); return f;
}
std::vector<uint8_t> Subscribe(const std::string &topic, uint16_t pid=1){
  std::vector<uint8_t> rem;
  rem.push_back((pid>>8)&0xFF); rem.push_back(pid&0xFF);
  app(rem,mstr(topic)); rem.push_back(0x00);
  std::vector<uint8_t> f; f.push_back(0x82);
  app(f,varlen(rem.size())); app(f,rem); return f;
}
Ptr<Packet> ToPkt(const std::vector<uint8_t>&v){
  return Create<Packet>(v.data(),v.size());
}
} // namespace Mqtt

// ════════════════════════════════════════════════════════════════════════════
//  WiFi helper (shared)
// ════════════════════════════════════════════════════════════════════════════
static NetDeviceContainer WNet(NodeContainer nc, const std::string& ssid,
                                YansWifiPhyHelper& phy){
  WifiHelper wifi; wifi.SetStandard(WIFI_STANDARD_80211b);
  WifiMacHelper mac;
  mac.SetType("ns3::AdhocWifiMac");
  wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
    "DataMode",StringValue("DsssRate1Mbps"));
  return wifi.Install(phy, mac, nc);
}

// ════════════════════════════════════════════════════════════════════════════
//  MqttBrokerApp  — accepts connections; tracks attacker socket for blocking
// ════════════════════════════════════════════════════════════════════════════
class MqttBrokerApp : public Application {
public:
  static TypeId GetTypeId(){
    static TypeId t=TypeId("MqttBrokerAppDef").SetParent<Application>()
      .SetGroupName("Tutorial").AddConstructor<MqttBrokerApp>(); return t;
  }
  void Setup(uint16_t port){ m_port=port; }

  // Called by defender to forcibly close the attacker connection
  void BlockAttacker(Ipv4Address ip){
    for(auto it=m_clientAddrs.begin(); it!=m_clientAddrs.end(); ++it){
      if(it->second==ip){
        NS_LOG_INFO("[BROKER] Closing socket for blocked IP "<<ip);
        it->first->Close();
        m_clients.erase(std::find(m_clients.begin(),m_clients.end(),it->first));
        m_clientAddrs.erase(it);
        return;
      }
    }
  }

private:
  void StartApplication() override {
    m_sock=Socket::CreateSocket(GetNode(),TcpSocketFactory::GetTypeId());
    m_sock->Bind(InetSocketAddress(Ipv4Address::GetAny(),m_port));
    m_sock->Listen();
    m_sock->SetAcceptCallback(
      MakeNullCallback<bool,Ptr<Socket>,const Address&>(),
      MakeCallback(&MqttBrokerApp::OnAccept,this));
  }
  void StopApplication() override {
    for(auto &s:m_clients) s->Close();
    m_clients.clear(); m_clientAddrs.clear();
    if(m_sock){m_sock->Close();m_sock=nullptr;}
  }
  void OnAccept(Ptr<Socket> s, const Address& addr){
    m_clients.push_back(s);
    InetSocketAddress ia=InetSocketAddress::ConvertFrom(addr);
    m_clientAddrs[s]=ia.GetIpv4();
    s->SetRecvCallback(MakeCallback(&MqttBrokerApp::OnRecv,this));
  }
  void OnRecv(Ptr<Socket> s){
    Ptr<Packet> p;
    while((p=s->Recv())){
      if(p->GetSize()<2) continue;
      uint8_t b[2]; p->CopyData(b,2);
      if(((b[0]>>4)&0x0F)==1) s->Send(Mqtt::ToPkt(Mqtt::ConnAck()));
    }
  }
  Ptr<Socket>              m_sock{nullptr};
  std::vector<Ptr<Socket>> m_clients;
  std::map<Ptr<Socket>,Ipv4Address> m_clientAddrs;
  uint16_t                 m_port{MQTT_PORT};
};

// ════════════════════════════════════════════════════════════════════════════
//  MqttSensorApp  — periodic PUBLISH to broker
// ════════════════════════════════════════════════════════════════════════════
class MqttSensorApp : public Application {
public:
  static TypeId GetTypeId(){
    static TypeId t=TypeId("MqttSensorAppDef").SetParent<Application>()
      .SetGroupName("Tutorial").AddConstructor<MqttSensorApp>(); return t;
  }
  void Setup(Ipv4Address br, uint16_t port,
             const std::string &cid, const std::string &topic,
             double interval, double stopTime){
    m_br=br; m_port=port; m_cid=cid; m_topic=topic;
    m_interval=Seconds(interval); m_stopAt=Seconds(stopTime);
  }
private:
  void StartApplication() override {
    m_sock=Socket::CreateSocket(GetNode(),TcpSocketFactory::GetTypeId());
    m_sock->SetConnectCallback(
      MakeCallback(&MqttSensorApp::OnConn,this),
      MakeNullCallback<void,Ptr<Socket>>());
    m_sock->Connect(InetSocketAddress(m_br,m_port));
  }
  void StopApplication() override {
    m_event.Cancel();
    if(m_sock){m_sock->Close();m_sock=nullptr;}
  }
  void OnConn(Ptr<Socket> s){
    s->Send(Mqtt::ToPkt(Mqtt::Connect(m_cid)));
    Simulator::Schedule(Seconds(0.05),&MqttSensorApp::SendPub,this);
  }
  void SendPub(){
    if(Simulator::Now()>=m_stopAt) return;
    if(m_sock) m_sock->Send(Mqtt::ToPkt(Mqtt::Publish(m_topic,"value:"+
      std::to_string((int)(rand()%100)))));
    m_event=Simulator::Schedule(m_interval,&MqttSensorApp::SendPub,this);
  }
  Ipv4Address  m_br;
  uint16_t     m_port{MQTT_PORT};
  std::string  m_cid, m_topic;
  Time         m_interval, m_stopAt;
  Ptr<Socket>  m_sock{nullptr};
  EventId      m_event;
};

// ════════════════════════════════════════════════════════════════════════════
//  MqttAttackApp  — DDoS
// ════════════════════════════════════════════════════════════════════════════
class MqttAttackApp : public Application {
public:
  static TypeId GetTypeId(){
    static TypeId t=TypeId("MqttAttackAppDef").SetParent<Application>()
      .SetGroupName("Tutorial").AddConstructor<MqttAttackApp>(); return t;
  }
  void Setup(Ipv4Address br, uint16_t port, int mode, double stopTime){
    m_br=br; m_port=port; m_mode=mode; m_stopAt=Seconds(stopTime);
  }
  void SetMode(int m){ m_mode=m; }
  bool IsSuspended() const { return m_suspended; }
  void Suspend(){ m_suspended=true; m_event.Cancel(); }
  void Resume(){ if(m_suspended){ m_suspended=false; ScheduleNext(); } }

private:
  void StartApplication() override { ScheduleNext(); }
  void StopApplication() override {
    m_event.Cancel();
    if(m_sock){m_sock->Close();m_sock=nullptr;}
  }
  void ScheduleNext(){
    if(m_suspended) return;
    m_event=Simulator::Schedule(Seconds(ATK[m_mode].delta),
                                &MqttAttackApp::DoAttack,this);
  }
  void DoAttack(){
    if(Simulator::Now()>=m_stopAt||m_suspended) return;
    m_sock=Socket::CreateSocket(GetNode(),TcpSocketFactory::GetTypeId());
    m_sock->Connect(InetSocketAddress(m_br,m_port));
    std::string cid="Atk_"+std::to_string(rand()%9999);
    switch(m_mode){
      case 0: // SYN flood — just connect, never complete
        break;
      case 1: // BASIC CONNECT flood
        m_sock->SetConnectCallback(MakeCallback(&MqttAttackApp::SendBasic,this),
          MakeNullCallback<void,Ptr<Socket>>()); break;
      case 2: // DELAY
        m_sock->SetConnectCallback(MakeCallback(&MqttAttackApp::SendDelay,this),
          MakeNullCallback<void,Ptr<Socket>>()); break;
      case 3: // INVSUB
        m_sock->SetConnectCallback(MakeCallback(&MqttAttackApp::SendInvSub,this),
          MakeNullCallback<void,Ptr<Socket>>()); break;
      case 4: // WILL
        m_sock->SetConnectCallback(MakeCallback(&MqttAttackApp::SendWill,this),
          MakeNullCallback<void,Ptr<Socket>>()); break;
    }
    ScheduleNext();
  }
  void SendBasic(Ptr<Socket> s){
    s->Send(Mqtt::ToPkt(Mqtt::Connect("Flood_"+std::to_string(rand()%9999))));
  }
  void SendDelay(Ptr<Socket> s){
    Simulator::Schedule(Seconds(0.5),&MqttAttackApp::SendBasic,this,s);
  }
  void SendInvSub(Ptr<Socket> s){
    s->Send(Mqtt::ToPkt(Mqtt::Connect("InvSub_"+std::to_string(rand()%9999))));
    Simulator::Schedule(Seconds(0.1),[s](){
      s->Send(Mqtt::ToPkt(Mqtt::Subscribe("$SYS/#invalid//topic")));
    });
  }
  void SendWill(Ptr<Socket> s){
    std::string wm(120,'X');
    s->Send(Mqtt::ToPkt(Mqtt::Connect("Will_"+std::to_string(rand()%9999),
                                      true,"will/topic",wm)));
  }

  Ipv4Address m_br;
  uint16_t    m_port{MQTT_PORT};
  int         m_mode{0};
  bool        m_suspended{false};
  Time        m_stopAt;
  Ptr<Socket> m_sock{nullptr};
  EventId     m_event;
};

// ════════════════════════════════════════════════════════════════════════════
//  GLOBAL APPLICATION POINTERS (set in main, used by callbacks)
// ════════════════════════════════════════════════════════════════════════════
static Ptr<MqttBrokerApp>  g_brokerApp;
static Ptr<MqttAttackApp>  g_attackApp;

// ════════════════════════════════════════════════════════════════════════════
//  DEFENDER — feature extraction + Python bridge call + action enforcement
// ════════════════════════════════════════════════════════════════════════════

// Compute 12 flow features that match your model's training features:
//   Time, time_delta, Length, has_mqtt_port,
//   flag_syn, flag_ack, flag_fin, flag_rst, flag_psh, flag_urg,
//   to_mqtt, from_mqtt
//
// We approximate these from FlowMonitor statistics over the last
// g_defEvalInterval seconds.  The 20-packet sequence is synthesised
// as g_defEvalInterval × pps replicas of the per-step features.

struct NetFeatures {
  double pkt_rate;     // packets / second to broker
  double byte_rate;    // bytes / second to broker
  double syn_ratio;    // fraction of SYN-like flows (new flows / total)
  double loss_ratio;   // lost packets / sent packets
  double avg_pkt_size; // bytes per packet
  bool   has_mqtt_port;
  bool   to_mqtt;
  bool   from_mqtt;
};

static NetFeatures g_prevFeatures;
static double      g_prevMeasureTime = 0.0;

static NetFeatures ExtractFeatures(){
  g_mon->CheckForLostPackets();
  auto stats  = g_mon->GetFlowStats();
  auto clsMap = g_cls;

  double totalPkts=0, totalBytes=0, lostPkts=0, synFlows=0, allFlows=0;

  for(auto &kv : stats){
    FlowId fid=kv.first;
    auto &fs=kv.second;
    Ipv4FlowClassifier::FiveTuple ft=clsMap->FindFlow(fid);

    // Only consider flows going TO the broker (attacker or sensors → broker)
    if(ft.destinationAddress != g_brokerIP) continue;

    allFlows++;
    totalPkts  += fs.txPackets;
    totalBytes += fs.txBytes;
    lostPkts   += fs.lostPackets;

    // New TCP connections (SYN-like) — approximated by flows with very few packets
    if(fs.txPackets <= 3) synFlows++;
  }

  double dt = g_defEvalInterval;

  NetFeatures f;
  f.pkt_rate      = (dt > 0) ? totalPkts  / dt : 0.0;
  f.byte_rate     = (dt > 0) ? totalBytes / dt : 0.0;
  f.avg_pkt_size  = (totalPkts > 0) ? totalBytes / totalPkts : 0.0;
  f.syn_ratio     = (allFlows  > 0) ? synFlows  / allFlows  : 0.0;
  f.loss_ratio    = (totalPkts > 0) ? lostPkts  / totalPkts : 0.0;
  f.has_mqtt_port = (totalPkts > 0);
  f.to_mqtt       = (totalPkts > 0);
  f.from_mqtt     = false; // outbound (broker → client) not tracked separately here

  return f;
}

// Build a 20-row CSV (one synthetic "packet" per row) from the features above
// to match the seq_len=20 window your model expects.
static void WriteDefenderQuery(const NetFeatures& f, const std::string& csvPath){
  std::ofstream o(csvPath);
  // Header matching rl_env.py add_features() output
  o << "Time,time_delta,Length,has_mqtt_port,"
    << "flag_syn,flag_ack,flag_fin,flag_rst,flag_psh,flag_urg,"
    << "to_mqtt,from_mqtt\n";

  double now = Simulator::Now().GetSeconds();
  double step = g_defEvalInterval / 20.0;

  // flag_syn is proportional to syn_ratio; flag_ack is the complement
  int flag_syn = (f.syn_ratio > 0.4) ? 1 : 0;
  int flag_ack = (f.syn_ratio < 0.6) ? 1 : 0;
  int flag_rst = (f.loss_ratio > 0.3) ? 1 : 0;
  int flag_psh = (f.avg_pkt_size > 100) ? 1 : 0;
  int flag_fin = 0, flag_urg = 0;

  for(int i = 0; i < 20; i++){
    double t   = now - g_defEvalInterval + i * step;
    double len = f.avg_pkt_size + (rand() % 10 - 5); // small jitter
    o << std::fixed << std::setprecision(6)
      << t << ","
      << step << ","
      << len << ","
      << (int)f.has_mqtt_port << ","
      << flag_syn << ","
      << flag_ack << ","
      << flag_fin << ","
      << flag_rst << ","
      << flag_psh << ","
      << flag_urg << ","
      << (int)f.to_mqtt << ","
      << (int)f.from_mqtt << "\n";
  }
}

// Parse defender_result.json  {"action": 2, "det_prob": 0.91, "action_name": "TEMP_BLOCK_IP"}
static int ParseDefenderResult(const std::string& jsonPath, double& prob){
  std::ifstream f(jsonPath);
  if(!f.good()) return 0;
  std::string line, content; while(std::getline(f,line)) content+=line;
  auto extract=[&](const std::string& key) -> std::string {
    auto pos=content.find("\""+key+"\"");
    if(pos==std::string::npos) return "";
    pos=content.find(":",pos); if(pos==std::string::npos) return "";
    pos++; while(pos<content.size()&&content[pos]==' ') pos++;
    std::string val;
    if(content[pos]=='"'){ pos++;
      while(pos<content.size()&&content[pos]!='"') val+=content[pos++];
    } else {
      while(pos<content.size()&&content[pos]!=','&&content[pos]!='}'&&content[pos]!=' ')
        val+=content[pos++];
    }
    return val;
  };
  try{ prob=std::stod(extract("det_prob")); }catch(...){ prob=0.0; }
  try{ return std::stoi(extract("action")); }catch(...){ return 0; }
}

// Enforce the chosen action in the simulation
static void EnforceDefenderAction(int action, bool attackDetected){
  NS_LOG_INFO("[DEFENDER t=" << Simulator::Now().GetSeconds() << "s] "
    << "Action=" << action << " (" << DEF_ACTION_NAMES[action] << ")"
    << "  det_prob=" << std::fixed << std::setprecision(3) << g_defLastDetProb
    << (attackDetected ? "  *** ATTACK MITIGATED ***" : ""));

  g_defActions[action]++;
  g_defLastAction = action;

  // Actions that immediately block / disconnect attacker
  bool shouldBlock = (action == 2  ||  // TEMP_BLOCK_IP
                      action == 3  ||  // PERM_BLOCK_IP
                      action == 4  ||  // DROP_SYN
                      action == 5  ||  // DROP_CONNECT
                      action == 9  ||  // DISCONNECT
                      action == 10 ||  // QUARANTINE
                      action == 11);   // ISOLATE_NODE

  // Actions that suspend (throttle) attacker
  bool shouldThrottle = (action == 1  ||  // RATE_LIMIT_IP
                         action == 6  ||  // DELAY_CONNECT
                         action == 7  ||  // LIMIT_PUBLISH
                         action == 8  ||  // BLOCK_SUBSCRIBE
                         action == 12);   // REDUCE_QOS

  // Actions that de-escalate (resume attacker if blocked)
  bool shouldRelease = (action == 0  ||  // ALLOW
                        action == 15);   // DEESCALATE

  if(shouldBlock && !g_attackerBlocked){
    g_attackerBlocked = true;
    if(g_attackApp) g_attackApp->Suspend();
    if(g_brokerApp) g_brokerApp->BlockAttacker(g_attackerIP);
    NS_LOG_INFO("[DEFENDER] Attacker BLOCKED at broker.");
  }

  if(shouldThrottle && !g_attackerBlocked){
    // Partial throttle: suspend attack for half a window then resume
    if(g_attackApp) g_attackApp->Suspend();
    Simulator::Schedule(Seconds(g_defEvalInterval/2.0),[](){ 
      if(g_attackApp && !g_attackerBlocked) g_attackApp->Resume();
    });
    NS_LOG_INFO("[DEFENDER] Attacker THROTTLED for " << g_defEvalInterval/2.0 << "s.");
  }

  if(shouldRelease && g_attackerBlocked){
    g_attackerBlocked = false;
    if(g_attackApp) g_attackApp->Resume();
    NS_LOG_INFO("[DEFENDER] Blocker released — traffic allowed.");
  }

  if(action == 14) g_defEscLevel = std::min(g_defEscLevel+1, 5);
  if(action == 15) g_defEscLevel = std::max(g_defEscLevel-1, 0);

  // Update NetAnim broker colour to reflect defence state
  if(g_anim){
    if(shouldBlock || g_attackerBlocked){
      // Orange broker = attack blocked
      g_anim->UpdateNodeColor(g_brokerApp->GetNode(), 255, 165, 0);
    } else if(action == 0 || action == 13 || action == 15){
      // Green broker = all clear
      g_anim->UpdateNodeColor(g_brokerApp->GetNode(), 34, 180, 100);
    } else {
      // Amber broker = throttling
      g_anim->UpdateNodeColor(g_brokerApp->GetNode(), 255, 200, 0);
    }
  }
}

// Write one row to defender_log.csv
static std::ofstream g_defLog;
static void WriteDefenderLogRow(int action, double detProb,
                                 bool blocked, const NetFeatures& f){
  g_defLog << std::fixed << std::setprecision(4)
    << Simulator::Now().GetSeconds() << ","
    << action << ","
    << DEF_ACTION_NAMES[action] << ","
    << detProb << ","
    << (int)blocked << ","
    << g_defEscLevel << ","
    << f.pkt_rate << ","
    << f.byte_rate << ","
    << f.syn_ratio << ","
    << f.loss_ratio << "\n";
  g_defLog.flush();
}

// ════════════════════════════════════════════════════════════════════════════
//  MAIN DEFENDER CALLBACK — runs every g_defEvalInterval seconds
// ════════════════════════════════════════════════════════════════════════════
static void DefenderEval(){
  if(Simulator::Now().GetSeconds() > g_simTime) return;

  // 1. Extract network features from FlowMonitor
  NetFeatures feats = ExtractFeatures();

  // 2. Write query CSV for Python bridge
  std::string queryPath  = Out("defender_query.csv");
  std::string resultPath = Out("defender_result.json");
  WriteDefenderQuery(feats, queryPath);

  // 3. Call Python bridge (loads your saved weights, runs inference)
std::string cmd =
    "/home/ja/ns-allinone-3.46.1/ns-3.46.1/defender_env/bin/python3 "
    + DEFENDER_SCRIPT
    + " --query "    + queryPath
    + " --out "      + resultPath
    + " --weights "  + DEFENDER_WEIGHTS_DIR
    + " --detector " + ACTIVE_DETECTOR
    + " 2>/dev/null";
    
  int ret = system(cmd.c_str());

  // 4. Parse result
  double detProb = 0.0;
  int action = 0;
  if(ret == 0){
    action = ParseDefenderResult(resultPath, detProb);
  } else {
    // Bridge failed — fall back to a simple threshold rule
    detProb = feats.syn_ratio * 0.6 + feats.loss_ratio * 0.4;
    action  = (detProb > 0.6) ? 2 : (detProb > 0.35) ? 1 : 0;
    NS_LOG_WARN("[DEFENDER] Python bridge failed (ret="<<ret
      <<") — using fallback rule, action="<<action);
  }
  g_defLastDetProb = detProb;

  bool attackDetected = (detProb >= 0.5);
  bool attackActive   = (Simulator::Now().GetSeconds() >= g_attackStart);

  // Update TP/FP/TN/FN
  if(attackActive && attackDetected)  g_defTP++;
  else if(attackActive)               g_defFN++;
  else if(!attackActive && attackDetected) g_defFP++;
  else                                g_defTN++;

  // 5. Enforce the action
  EnforceDefenderAction(action, attackDetected);

  // 6. Log
  WriteDefenderLogRow(action, detProb, g_attackerBlocked, feats);

  // 7. Reschedule
  Simulator::Schedule(Seconds(g_defEvalInterval), &DefenderEval);
}

// ════════════════════════════════════════════════════════════════════════════
//  ATTACKER EVAL  (unchanged Q-table logic from original)
// ════════════════════════════════════════════════════════════════════════════
static double GetLossRatio(){
  g_mon->CheckForLostPackets();
  uint64_t tx=0,lost=0;
  for(auto &kv:g_mon->GetFlowStats()){
    tx+=kv.second.txPackets; lost+=kv.second.lostPackets;
  }
  return tx>0 ? (double)lost/tx : 0.0;
}
static void RLEval(){
  if(Simulator::Now().GetSeconds()>g_simTime) return;
  double loss=GetLossRatio();
  double reward=-loss*5.0 + (1.0-loss)*2.0;
  if(g_attackerBlocked) reward-=3.0;   // attacker penalised when blocked
  g_rl.q[g_rl.mode]+= LR*(reward+GAMMA*
    *std::max_element(g_rl.q,g_rl.q+N_MODES)-g_rl.q[g_rl.mode]);
  int bestMode=std::max_element(g_rl.q,g_rl.q+N_MODES)-g_rl.q;
  int newMode;
  if((double)rand()/RAND_MAX < g_rl.eps) newMode=rand()%N_MODES;
  else newMode=bestMode;
  g_rl.eps=std::max(g_rl.eps*EPS_DECAY,EPS_FLOOR);
  g_rl.mode=newMode; g_rl.steps++;
  g_rl.mU[newMode]++;
  if(g_rl.app) DynamicCast<MqttAttackApp>(g_rl.app)->SetMode(newMode);
  NS_LOG_INFO("[ATTACKER t="<<Simulator::Now().GetSeconds()<<"s]"
    <<" mode="<<newMode<<"("<<ATK[newMode].shortName<<")"
    <<"  reward="<<std::fixed<<std::setprecision(3)<<reward
    <<"  eps="<<g_rl.eps
    <<"  blocked="<<g_attackerBlocked);
  Simulator::Schedule(Seconds(g_evalInterval),&RLEval);
}

// ════════════════════════════════════════════════════════════════════════════
//  TIMESERIES SNAPSHOT
// ════════════════════════════════════════════════════════════════════════════
static std::ofstream g_tsFile;
static void SnapTS(){
  if(Simulator::Now().GetSeconds()>g_simTime) return;
  double loss=GetLossRatio();
  g_tsFile<<std::fixed<<std::setprecision(2)
    <<Simulator::Now().GetSeconds()<<","<<loss<<","
    <<g_rl.mode<<","<<ATK[g_rl.mode].shortName<<","
    <<g_defLastAction<<","<<DEF_ACTION_NAMES[g_defLastAction]<<","
    <<g_defLastDetProb<<","<<(int)g_attackerBlocked<<"\n";
  g_tsFile.flush();
  Simulator::Schedule(Seconds(1.0),&SnapTS);
}

// ════════════════════════════════════════════════════════════════════════════
//  WRITE OUTPUT CSVs
// ════════════════════════════════════════════════════════════════════════════
static void WriteFlowsCsv(){
  std::ofstream f(Out("flows.csv"));
  f<<"flow_id,src_ip,src_port,dst_ip,dst_port,proto,"
   <<"tx_pkts,tx_bytes,rx_pkts,rx_bytes,lost_pkts,"
   <<"delay_sum_ns,jitter_sum_ns\n";
  for(auto &kv:g_mon->GetFlowStats()){
    auto ft=g_cls->FindFlow(kv.first);
    auto &s=kv.second;
    f<<kv.first<<","
     <<ft.sourceAddress<<","<<ft.sourcePort<<","
     <<ft.destinationAddress<<","<<ft.destinationPort<<","
     <<(int)ft.protocol<<","
     <<s.txPackets<<","<<s.txBytes<<","
     <<s.rxPackets<<","<<s.rxBytes<<","
     <<s.lostPackets<<","
     <<s.delaySum.GetNanoSeconds()<<","
     <<s.jitterSum.GetNanoSeconds()<<"\n";
  }
}
static void WriteSumCsv(){
  std::ofstream f(Out("summary.csv"));
  f<<"Section,Key,Value\n";
  f<<"Topology,Brokers,1\n";
  f<<"Topology,Sensors,6\n";
  f<<"Topology,Attackers,1\n";
  f<<"Topology,Defenders,1\n";
  f<<"Simulation,SimTime,"<<g_simTime<<"\n";
  f<<"Simulation,AttackStart,"<<g_attackStart<<"\n";
  f<<"Simulation,DefEvalInterval,"<<g_defEvalInterval<<"\n";
  f<<"Defender,ActiveModel,"<<ACTIVE_DETECTOR<<"\n";
  f<<"Defender,LastAction,"<<g_defLastAction<<"\n";
  f<<"Defender,TP,"<<g_defTP<<"\n";
  f<<"Defender,FP,"<<g_defFP<<"\n";
  f<<"Defender,TN,"<<g_defTN<<"\n";
  f<<"Defender,FN,"<<g_defFN<<"\n";
  double tpr= (g_defTP+g_defFN)>0 ? (double)g_defTP/(g_defTP+g_defFN) : 0.0;
  double fpr= (g_defFP+g_defTN)>0 ? (double)g_defFP/(g_defFP+g_defTN) : 0.0;
  f<<"Defender,TPR,"<<std::fixed<<std::setprecision(4)<<tpr<<"\n";
  f<<"Defender,FPR,"<<std::fixed<<std::setprecision(4)<<fpr<<"\n";
  f<<"Attacker,FinalMode,"<<g_rl.mode<<"\n";
  f<<"Attacker,FinalModeName,"<<ATK[g_rl.mode].shortName<<"\n";
  f<<"Attacker,Steps,"<<g_rl.steps<<"\n";
  f<<"Attacker,FinalEpsilon,"<<g_rl.eps<<"\n";
  for(int m=0;m<N_MODES;m++)
    f<<"Attacker,Q_"<<ATK[m].shortName<<","<<g_rl.q[m]<<"\n";
}

// ════════════════════════════════════════════════════════════════════════════
//  MAIN
// ════════════════════════════════════════════════════════════════════════════
int main(int argc, char *argv[])
{
  CommandLine cmd(__FILE__);
  cmd.AddValue("simTime",        "Simulation time (s)",       g_simTime);
  cmd.AddValue("attackStart",    "Attack start time (s)",     g_attackStart);
  cmd.AddValue("evalInterval",   "Attacker eval interval (s)",  g_evalInterval);
  cmd.AddValue("defInterval",    "Defender eval interval (s)",g_defEvalInterval);
  cmd.AddValue("epsilon",        "Initial epsilon",        g_epsilon);
  cmd.AddValue("seed",           "Random seed",               g_seed);
  cmd.AddValue("outDir",         "Output directory",          g_outDir);
  cmd.AddValue("weightsDir",     "Defender weights directory",DEFENDER_WEIGHTS_DIR);
  cmd.AddValue("defScript",      "Defender Python script",    DEFENDER_SCRIPT);
  cmd.AddValue("detector",       "Detector type",             ACTIVE_DETECTOR);
  cmd.Parse(argc, argv);

  Time::SetResolution(Time::NS);
  RngSeedManager::SetSeed(g_seed);
  LogComponentEnable("MqttDefended1Broker", LOG_LEVEL_INFO);
  srand(g_seed);

  MkDir(g_outDir); MkDir(g_outDir+"/pcap");

  // ── Open log files ────────────────────────────────────────────────────────
  g_defLog.open(Out("defender_log.csv"));
  g_defLog << "time_s,action_id,action_name,det_prob,blocked,"
           << "esc_level,pkt_rate,byte_rate,syn_ratio,loss_ratio\n";

  g_tsFile.open(Out("timeseries.csv"));
  g_tsFile << "time_s,loss_ratio,atk_mode,atk_mode_name,"
           << "def_action,def_action_name,det_prob,blocked\n";

  // ── Nodes ─────────────────────────────────────────────────────────────────
  NodeContainer brokers;   brokers.Create(1);   // Node 0
  NodeContainer sensors;   sensors.Create(6);   // Nodes 1-6
  NodeContainer attackers; attackers.Create(1); // Node 7
  NodeContainer defenders; defenders.Create(1); // Node 8  ← NEW

  NodeContainer allNodes;
  allNodes.Add(brokers); allNodes.Add(sensors);
  allNodes.Add(attackers); allNodes.Add(defenders);

  // ── Mobility ─────────────────────────────────────────────────────────────
  MobilityHelper mob;
  mob.SetMobilityModel("ns3::ConstantPositionMobilityModel");
  {
    Ptr<ListPositionAllocator> p = CreateObject<ListPositionAllocator>();
    p->Add(Vector(50, 50, 0));   // Broker — centre
    for(int i=0;i<6;i++){        // Sensors — circle r=35
      double angle = i*(2.0*M_PI/6.0) - (M_PI/2.0);
      p->Add(Vector(50+35*cos(angle), 50+35*sin(angle), 0));
    }
    p->Add(Vector(50, 92, 0));   // Attacker — bottom
    p->Add(Vector(90, 50, 0));   // Defender — right side
    mob.SetPositionAllocator(p);
    mob.Install(allNodes);
  }

  // ── WiFi ──────────────────────────────────────────────────────────────────
  YansWifiChannelHelper ch = YansWifiChannelHelper::Default();
  YansWifiPhyHelper phy; phy.SetChannel(ch.Create());
  NetDeviceContainer devs = WNet(allNodes, "mqtt-defended", phy);
  phy.EnablePcap(g_outDir+"/pcap/broker",   devs.Get(0), true);
  phy.EnablePcap(g_outDir+"/pcap/attacker", devs.Get(7), true);
  phy.EnablePcap(g_outDir+"/pcap/defender", devs.Get(8), true);

  // ── Internet stack ────────────────────────────────────────────────────────
  InternetStackHelper stack; stack.Install(allNodes);
  Ipv4AddressHelper ip4;
  ip4.SetBase("10.0.0.0", "255.255.255.0");
  Ipv4InterfaceContainer ifc = ip4.Assign(devs);
  Ipv4GlobalRoutingHelper::PopulateRoutingTables();

  g_brokerIP   = ifc.GetAddress(0); // 10.0.0.1
  g_attackerIP = ifc.GetAddress(7); // 10.0.0.8
  g_defenderIP = ifc.GetAddress(8); // 10.0.0.9
  NS_LOG_INFO("Broker="<<g_brokerIP
    <<"  Attacker="<<g_attackerIP
    <<"  Defender="<<g_defenderIP);

  // ── Broker app ────────────────────────────────────────────────────────────
  {
    g_brokerApp = CreateObject<MqttBrokerApp>();
    g_brokerApp->Setup(MQTT_PORT);
    brokers.Get(0)->AddApplication(g_brokerApp);
    g_brokerApp->SetStartTime(Seconds(0.5));
    g_brokerApp->SetStopTime(Seconds(g_simTime));
  }

  // ── Sensor apps ───────────────────────────────────────────────────────────
  struct SCfg{ const char *topic; double interval; int si; };
  SCfg cfgs[]={
    {"sensors/temperature_humidity", 2.0, 0},
    {"sensors/water_level",          3.0, 1},
    {"sensors/ultrasonic",           1.0, 2},
    {"sensors/flame_ir",             2.0, 3},
    {"sensors/motion",               1.0, 4},
    {"sensors/light",                2.0, 5},
  };
  const char *sNames[]={"TempHumidity","WaterLevel","Ultrasonic",
                        "FlameIR","Motion","Light"};
  for(auto &c:cfgs){
    Ptr<MqttSensorApp> a = CreateObject<MqttSensorApp>();
    a->Setup(g_brokerIP, MQTT_PORT,
             std::string("Sensor_")+sNames[c.si],
             c.topic, c.interval, g_simTime);
    sensors.Get(c.si)->AddApplication(a);
    a->SetStartTime(Seconds(1.0+c.si*0.1));
    a->SetStopTime(Seconds(g_simTime));
  }

  // ── Attack app ────────────────────────────────────────────────────────────
  g_rl.mode = 0;
  {
    g_attackApp = CreateObject<MqttAttackApp>();
    g_attackApp->Setup(g_brokerIP, MQTT_PORT, g_rl.mode, g_simTime);
    attackers.Get(0)->AddApplication(g_attackApp);
    g_attackApp->SetStartTime(Seconds(g_attackStart));
    g_attackApp->SetStopTime(Seconds(g_simTime));
    g_rl.app = g_attackApp;
  }

  // ── FlowMonitor ───────────────────────────────────────────────────────────
  FlowMonitorHelper fmh;
  g_mon = fmh.InstallAll();
  g_cls = DynamicCast<Ipv4FlowClassifier>(fmh.GetClassifier());

  // ── Schedule callbacks ───────────────────────────────────────────────────
  // Attacker
  Simulator::Schedule(Seconds(g_attackStart + g_evalInterval), &RLEval);
  // Defender (starts a few seconds after attack begins)
  Simulator::Schedule(Seconds(g_attackStart + g_defEvalInterval), &DefenderEval);
  // Timeseries snapshot
  Simulator::Schedule(Seconds(1.0), &SnapTS);

  // ── NetAnim ───────────────────────────────────────────────────────────────
  std::string animFile = Out("mqtt-defended-anim.xml");
  AnimationInterface anim(animFile);
  g_anim = &anim;

  // ── Broker (green = healthy, orange when under attack)
  anim.SetConstantPosition(brokers.Get(0), 50.0, 50.0);
  anim.UpdateNodeDescription(brokers.Get(0),
    "MQTT BROKER\n10.0.0.1 | Port:1883\n[Protected by AI Defender]");
  anim.UpdateNodeColor(brokers.Get(0), 34, 180, 100);
  anim.UpdateNodeSize(brokers.Get(0)->GetId(), 5.5, 5.5);

  // ── Sensors (blue)
  struct SInfo{ const char *label; };
  SInfo sinfo[]={
    {"S1: Temp & Humidity\n10.0.0.2 | DHT22\nInterval:2s"},
    {"S2: Water Level\n10.0.0.3 | HC-SR04\nInterval:3s"},
    {"S3: Ultrasonic\n10.0.0.4 | HC-SR04\nInterval:1s"},
    {"S4: Flame / IR\n10.0.0.5 | KY-026\nInterval:2s"},
    {"S5: Motion (PIR)\n10.0.0.6 | HC-SR501\nInterval:1s"},
    {"S6: Light (LDR)\n10.0.0.7 | BH1750\nInterval:2s"},
  };
  for(int i=0;i<6;i++){
    double angle = i*(2.0*M_PI/6.0)-(M_PI/2.0);
    double x = 50.0+35.0*cos(angle);
    double y = 50.0+35.0*sin(angle);
    anim.SetConstantPosition(sensors.Get(i), x, y);
    anim.UpdateNodeDescription(sensors.Get(i), sinfo[i].label);
    anim.UpdateNodeColor(sensors.Get(i), 70, 130, 255);
    anim.UpdateNodeSize(sensors.Get(i)->GetId(), 3.5, 3.5);
  }

  // ── Attacker (red)
  anim.SetConstantPosition(attackers.Get(0), 50.0, 92.0);
  anim.UpdateNodeDescription(attackers.Get(0),
    "! ATTACKER !\n10.0.0.8 | DDoS Agent\n5 Attack Modes (SYN/BASIC/DELAY/INVSUB/WILL)");
  anim.UpdateNodeColor(attackers.Get(0), 220, 40, 40);
  anim.UpdateNodeSize(attackers.Get(0)->GetId(), 4.5, 4.5);

  // ── Defender (purple) — your AI IDS/IPS node
  anim.SetConstantPosition(defenders.Get(0), 90.0, 50.0);
  anim.UpdateNodeDescription(defenders.Get(0),
    "AI DEFENDER\n10.0.0.9 | CNN-BiLSTM-Attn\n16 Mitigation Actions");
  anim.UpdateNodeColor(defenders.Get(0), 148, 0, 211);   // purple
  anim.UpdateNodeSize(defenders.Get(0)->GetId(), 4.5, 4.5);

  anim.EnablePacketMetadata(true);
  NS_LOG_INFO("NetAnim → " << animFile);

  // ── Run ───────────────────────────────────────────────────────────────────
  Simulator::Stop(Seconds(g_simTime + 1.0));
  NS_LOG_INFO("=== MQTT 1-Broker AI-Defended Simulation Starting ===");
  NS_LOG_INFO("Attacker DDoS starts at t=" << g_attackStart << "s");
  NS_LOG_INFO("Defender ("<<ACTIVE_DETECTOR<<") evaluates every "
              << g_defEvalInterval << "s");
  Simulator::Run();

  // ── Outputs ───────────────────────────────────────────────────────────────
  g_mon->CheckForLostPackets();
  g_mon->SerializeToXmlFile(Out("mqtt-defended-flowmonitor.xml"), true, true);
  WriteFlowsCsv();
  WriteSumCsv();
  g_defLog.close();
  g_tsFile.close();

  double tpr=(g_defTP+g_defFN)>0 ? 100.0*g_defTP/(g_defTP+g_defFN) : 0.0;
  double fpr=(g_defFP+g_defTN)>0 ? 100.0*g_defFP/(g_defFP+g_defTN) : 0.0;

  std::cout << "\n╔══════════════════════════════════════════════════════════╗\n";
  std::cout << "║  MQTT 1-Broker AI-Defended Simulation — Complete        ║\n";
  std::cout << "╚══════════════════════════════════════════════════════════╝\n\n";
  std::cout << "  Topology  : 1 Broker + 6 Sensors + 1 Attacker + 1 AI Defender\n";
  std::cout << "  Protocol  : MQTT 3.1.1 over TCP:1883\n";
  std::cout << "  Detector  : " << ACTIVE_DETECTOR << "\n";
  std::cout << "  Attack    : started at t=" << g_attackStart << "s\n\n";
  std::cout << "  DEFENDER RESULTS:\n";
  std::cout << "    TP=" << g_defTP << "  FP=" << g_defFP
            << "  TN=" << g_defTN << "  FN=" << g_defFN << "\n";
  std::cout << "    TPR=" << std::fixed << std::setprecision(1) << tpr << "%"
            << "   FPR=" << fpr << "%\n\n";
  std::cout << "  ATTACKER FINAL Q-TABLE:\n";
  for(int m=0;m<N_MODES;m++)
    std::cout << "    [" << m << "] " << std::setw(8) << ATK[m].shortName
              << "  Q=" << std::fixed << std::setprecision(3) << g_rl.q[m]
              << "  used=" << (int)g_rl.mU[m] << "\n";
  std::cout << "  steps=" << g_rl.steps << "  eps=" << g_rl.eps << "\n\n";
  std::cout << "  Output → " << g_outDir << "/\n";
  std::cout << "  NetAnim → open: " << animFile << "\n\n";

  Simulator::Destroy();
  NS_LOG_INFO("Done.");
  return 0;
}
