/* =============================================================================
 * NS-3  MQTT IoT Simulation — 2 Brokers, 15 Sensors, 2 Attackers + 2 AI DEFENDERS
 * =============================================================================
 *
 * TOPOLOGY  (Wireless 802.11b Ad-Hoc, two independent LANs)
 *
 *  LAN 0  (10.0.0.0/24)                 LAN 1  (10.1.0.0/24)
 *  ─────────────────────────────        ─────────────────────────────
 *  Node  IP             Role            Node  IP             Role
 *  ────  ─────────────  ──────          ────  ─────────────  ──────
 *    0   10.0.0.1       BROKER 0          10  10.1.0.1       BROKER 1
 *   1-8  10.0.0.2-9     Sensors 1-8      11-17 10.1.0.2-8   Sensors 9-15
 *    9   10.0.0.10      ATTACKER 0        18  10.1.0.9       ATTACKER 1
 *   19   10.0.0.20      AI DEFENDER 0     20  10.1.0.20      AI DEFENDER 1
 *
 * ATTACK MODES (5 modes, same as 1-broker variant):
 *   0 SYN    1 BASIC    2 DELAY    3 INVSUB    4 WILL
 *
 * DEFENDER ACTIONS (16 actions per defender, mirrors rl_env.py):
 *   0  ALLOW             9  DISCONNECT
 *   1  RATE_LIMIT_IP    10  QUARANTINE
 *   2  TEMP_BLOCK_IP    11  ISOLATE_NODE
 *   3  PERM_BLOCK_IP    12  REDUCE_QOS
 *   4  DROP_SYN         13  ALERT_ONLY
 *   5  DROP_CONNECT     14  ESCALATE
 *   6  DELAY_CONNECT    15  DEESCALATE
 *   7  LIMIT_PUBLISH
 *   8  BLOCK_SUBSCRIBE
 *
 * HOW IT WORKS:
 *   Each LAN has an independent AI Defender node that monitors its broker.
 *   Every g_defEvalInterval seconds each defender:
 *     1. Reads FlowMonitor stats for its LAN's broker
 *     2. Builds a 20×12 feature matrix and writes defender_query_N.csv
 *     3. Calls Python bridge → CNN-BiLSTM-Attn policy
 *     4. Reads defender_result_N.json → action ID
 *     5. Enforces action (throttle / block attacker socket)
 *     6. Updates NetAnim broker colour (green / amber / orange)
 *     7. Appends to defender_log_N.csv
 *
 * OUTPUT → defended_2broker_output/
 *   defender_log_0.csv / defender_log_1.csv   — per-defender decision logs
 *   timeseries.csv                            — per-second dual-LAN snapshot
 *   flows.csv                                 — FlowMonitor per-flow stats
 *   summary.csv                               — final TP/FP/TN/FN for both
 *   rl_log.csv                                — attacker Q-table evolution
 *   pcap/                                     — Wireshark captures
 *   mqtt-2broker-defended-anim.xml            — NetAnim animation
 *
 * BUILD:
 *   cp mqtt_2broker_defended.cc  $NS3_DIR/scratch/
 *   cp defender_ns3_bridge.py    $NS3_DIR/scratch/
 *   cd $NS3_DIR && ./ns3 build scratch/mqtt_2broker_defended
 *   ./ns3 run scratch/mqtt_2broker_defended
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
#include <map>
#include <cmath>
#include <cstdlib>
#include <sys/stat.h>

using namespace ns3;
NS_LOG_COMPONENT_DEFINE ("MqttDefended2Broker");

// ════════════════════════════════════════════════════════════════════════════
//  USER CONFIGURATION — edit these before running
// ════════════════════════════════════════════════════════════════════════════
static std::string DEFENDER_WEIGHTS_DIR =
    "/home/ja/Downloads";

static std::string ACTIVE_DETECTOR = "cnn_bilstm_attn";

static std::string DEFENDER_SCRIPT =
    "/home/ja/ns-allinone-3.46.1/ns-3.46.1/scratch/defender_ns3_bridge.py";

// ════════════════════════════════════════════════════════════════════════════
//  SIMULATION PARAMETERS
// ════════════════════════════════════════════════════════════════════════════
static const uint16_t MQTT_PORT      = 1883;
static double      g_simTime         = 120.0;
static double      g_attackStart     = 10.0;
static double      g_evalInterval    = 8.0;   // attacker eval period
static double      g_defEvalInterval = 4.0;   // defender eval period
static double      g_epsilon         = 0.90;
static uint32_t    g_seed            = 42;
static std::string g_outDir          = "defended_2broker_output";

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
//  DEFENDER ACTION NAMES
// ════════════════════════════════════════════════════════════════════════════
static const char* DEF_ACTION_NAMES[16] = {
  "ALLOW",           "RATE_LIMIT_IP",   "TEMP_BLOCK_IP",  "PERM_BLOCK_IP",
  "DROP_SYN",        "DROP_CONNECT",    "DELAY_CONNECT",  "LIMIT_PUBLISH",
  "BLOCK_SUBSCRIBE", "DISCONNECT",      "QUARANTINE",     "ISOLATE_NODE",
  "REDUCE_QOS",      "ALERT_ONLY",      "ESCALATE",       "DEESCALATE"
};

// ════════════════════════════════════════════════════════════════════════════
//  HELPERS
// ════════════════════════════════════════════════════════════════════════════
static std::string Out(const std::string& f){ return g_outDir+"/"+f; }
static void MkDir(const std::string& d){ mkdir(d.c_str(),0755); }

// ════════════════════════════════════════════════════════════════════════════
//  MQTT FRAME BUILDER
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
//  WiFi helper
// ════════════════════════════════════════════════════════════════════════════
static NetDeviceContainer WNet(NodeContainer nc, const std::string& ssid,
                                YansWifiPhyHelper& phy){
  WifiHelper wifi; wifi.SetStandard(WIFI_STANDARD_80211b);
  WifiMacHelper mac; mac.SetType("ns3::AdhocWifiMac");
  wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
    "DataMode",StringValue("DsssRate11Mbps"),
    "ControlMode",StringValue("DsssRate11Mbps"));
  return wifi.Install(phy, mac, nc);
}

// ════════════════════════════════════════════════════════════════════════════
//  MqttBrokerAppDef2 — accepts connections; supports per-IP blocking
// ════════════════════════════════════════════════════════════════════════════
class MqttBrokerAppDef2 : public Application {
public:
  static TypeId GetTypeId(){
    static TypeId t=TypeId("MqttBrokerAppDef2B").SetParent<Application>()
      .SetGroupName("Tutorial").AddConstructor<MqttBrokerAppDef2>(); return t;
  }
  void Setup(uint16_t port){ m_port=port; }

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
      MakeCallback(&MqttBrokerAppDef2::OnAccept,this));
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
    s->SetRecvCallback(MakeCallback(&MqttBrokerAppDef2::OnRecv,this));
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
//  MqttSensorAppDef2 — periodic PUBLISH
// ════════════════════════════════════════════════════════════════════════════
class MqttSensorAppDef2 : public Application {
public:
  static TypeId GetTypeId(){
    static TypeId t=TypeId("MqttSensorAppDef2B").SetParent<Application>()
      .SetGroupName("Tutorial").AddConstructor<MqttSensorAppDef2>(); return t;
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
      MakeCallback(&MqttSensorAppDef2::OnConn,this),
      MakeNullCallback<void,Ptr<Socket>>());
    m_sock->Connect(InetSocketAddress(m_br,m_port));
  }
  void StopApplication() override {
    m_event.Cancel();
    if(m_sock){m_sock->Close();m_sock=nullptr;}
  }
  void OnConn(Ptr<Socket> s){
    s->Send(Mqtt::ToPkt(Mqtt::Connect(m_cid)));
    Simulator::Schedule(Seconds(0.05),&MqttSensorAppDef2::SendPub,this);
  }
  void SendPub(){
    if(Simulator::Now()>=m_stopAt) return;
    if(m_sock) m_sock->Send(Mqtt::ToPkt(Mqtt::Publish(m_topic,
      "value:"+std::to_string((int)(rand()%100)))));
    m_event=Simulator::Schedule(m_interval,&MqttSensorAppDef2::SendPub,this);
  }
  Ipv4Address  m_br;
  uint16_t     m_port{MQTT_PORT};
  std::string  m_cid, m_topic;
  Time         m_interval, m_stopAt;
  Ptr<Socket>  m_sock{nullptr};
  EventId      m_event;
};

// ════════════════════════════════════════════════════════════════════════════
//  MqttAttackAppDef2 — DDoS with Suspend/Resume
// ════════════════════════════════════════════════════════════════════════════
class MqttAttackAppDef2 : public Application {
public:
  static TypeId GetTypeId(){
    static TypeId t=TypeId("MqttAttackAppDef2B").SetParent<Application>()
      .SetGroupName("Tutorial").AddConstructor<MqttAttackAppDef2>(); return t;
  }
  void Setup(Ipv4Address tgt, uint16_t port, int mode, double stopTime, int brokerId){
    m_tgt=tgt; m_port=port; m_mode=mode; m_stopAt=Seconds(stopTime); m_bid=brokerId;
  }
  void SetMode(int m){ m_mode=m; }
  int  GetMode() const { return m_mode; }
  bool IsSuspended() const { return m_suspended; }
  void Suspend(){ m_suspended=true; m_event.Cancel(); }
  void Resume(){ if(m_suspended){ m_suspended=false; SchedNext(); } }

private:
  void StartApplication() override { SchedNext(); }
  void StopApplication()  override {
    m_event.Cancel();
    for(auto &s:m_socks) s->Close();
    m_socks.clear();
  }
  void SchedNext(){
    if(m_suspended) return;
    double d=ATK[m_mode].delta;
    Ptr<UniformRandomVariable> u=CreateObject<UniformRandomVariable>();
    d*=(0.8+u->GetValue(0.0,0.4));
    m_event=Simulator::Schedule(Seconds(d),&MqttAttackAppDef2::Fire,this);
  }
  void Fire(){
    if(Simulator::Now()>=m_stopAt||m_suspended) return;
    Ptr<Socket> s=Socket::CreateSocket(GetNode(),TcpSocketFactory::GetTypeId());
    m_socks.push_back(s);
    int mode=m_mode; int bid=m_bid;
    s->SetConnectCallback(
      MakeBoundCallback(&MqttAttackAppDef2::OnConn,this,mode,bid),
      MakeNullCallback<void,Ptr<Socket>>());
    s->Connect(InetSocketAddress(m_tgt,m_port));
    SchedNext();
  }
  static void OnConn(MqttAttackAppDef2* self, int mode, int bid, Ptr<Socket> s){
    std::vector<uint8_t> f;
    std::string rnd=std::to_string(rand()%65535);
    switch(mode){
      case 0: f=Mqtt::Connect("syn_b"+std::to_string(bid)+"_"+rnd); break;
      case 1: f=Mqtt::Connect("flood_b"+std::to_string(bid)+"_"+rnd); break;
      case 2:
        Simulator::Schedule(MilliSeconds(500),[s,bid,rnd](){
          s->Send(Mqtt::ToPkt(Mqtt::Connect("delay_b"+std::to_string(bid)+"_"+rnd)));
        }); return;
      case 3: f=Mqtt::Subscribe("invalid/##/bad_topic",rand()%65535); break;
      case 4: f=Mqtt::Connect("will_b"+std::to_string(bid)+"_"+rnd,true,
                               "sensors/flame_ir",
                               "ALERT_"+std::to_string(rand()%1000)); break;
      default:f=Mqtt::Connect("atk_b"+std::to_string(bid)+"_"+rnd); break;
    }
    s->Send(Mqtt::ToPkt(f));
  }
  Ipv4Address              m_tgt; uint16_t m_port{MQTT_PORT};
  int                      m_mode{0}, m_bid{0};
  bool                     m_suspended{false};
  Time                     m_stopAt;
  EventId                  m_event;
  std::vector<Ptr<Socket>> m_socks;
};

// ════════════════════════════════════════════════════════════════════════════
//  GLOBAL POINTERS
// ════════════════════════════════════════════════════════════════════════════
static Ptr<MqttBrokerAppDef2>  g_brokerApp0, g_brokerApp1;
static Ptr<MqttAttackAppDef2>  g_attackApp0, g_attackApp1;
static Ptr<FlowMonitor>        g_mon;
static Ptr<Ipv4FlowClassifier> g_cls;
static AnimationInterface*     g_anim = nullptr;

static Ipv4Address g_broker0IP, g_broker1IP;
static Ipv4Address g_atk0IP,    g_atk1IP;
static Ipv4Address g_def0IP,    g_def1IP;

// ════════════════════════════════════════════════════════════════════════════
//  PER-DEFENDER STATE
// ════════════════════════════════════════════════════════════════════════════
struct DefState {
  int      lastAction    = 0;
  bool     blocked       = false;
  int      escLevel      = 0;
  double   lastDetProb   = 0.0;
  uint32_t TP=0, FP=0, TN=0, FN=0;
  uint32_t actions[16]  = {};
};
static DefState g_def0, g_def1;

// ════════════════════════════════════════════════════════════════════════════
//  PER-ATTACKER STATE
// ════════════════════════════════════════════════════════════════════════════
struct RLState2 {
  int      mode  = 0;
  int      steps = 0;
  double   q[N_MODES] = {};
  double   eps;
  uint32_t mU[N_MODES] = {};
  Ptr<MqttAttackAppDef2> app;
  RLState2() : eps(g_epsilon) {}
};
static RLState2 g_rl0, g_rl1;

// ════════════════════════════════════════════════════════════════════════════
//  FEATURE EXTRACTION (per-broker)
// ════════════════════════════════════════════════════════════════════════════
struct NetFeatures {
  double pkt_rate;
  double byte_rate;
  double syn_ratio;
  double loss_ratio;
  double avg_pkt_size;
  bool   has_mqtt_port;
  bool   to_mqtt;
  bool   from_mqtt;
};

static NetFeatures ExtractFeatures(Ipv4Address brokerIP){
  g_mon->CheckForLostPackets();
  auto stats = g_mon->GetFlowStats();

  double totalPkts=0, totalBytes=0, lostPkts=0, synFlows=0, allFlows=0;

  for(auto &kv : stats){
    FlowId fid=kv.first;
    auto &fs=kv.second;
    Ipv4FlowClassifier::FiveTuple ft=g_cls->FindFlow(fid);
    if(ft.destinationAddress != brokerIP) continue;
    allFlows++;
    totalPkts  += fs.txPackets;
    totalBytes += fs.txBytes;
    lostPkts   += fs.lostPackets;
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
  f.from_mqtt     = false;
  return f;
}

// ════════════════════════════════════════════════════════════════════════════
//  WRITE DEFENDER QUERY CSV
// ════════════════════════════════════════════════════════════════════════════
static void WriteDefenderQuery(const NetFeatures& f, const std::string& csvPath){
  std::ofstream o(csvPath);
  o << "Time,time_delta,Length,has_mqtt_port,"
    << "flag_syn,flag_ack,flag_fin,flag_rst,flag_psh,flag_urg,"
    << "to_mqtt,from_mqtt\n";

  double now  = Simulator::Now().GetSeconds();
  double step = g_defEvalInterval / 20.0;

  int flag_syn = (f.syn_ratio  > 0.4) ? 1 : 0;
  int flag_ack = (f.syn_ratio  < 0.6) ? 1 : 0;
  int flag_rst = (f.loss_ratio > 0.3) ? 1 : 0;
  int flag_psh = (f.avg_pkt_size > 100) ? 1 : 0;
  int flag_fin = 0, flag_urg = 0;

  for(int i=0; i<20; i++){
    double t   = now - g_defEvalInterval + i * step;
    double len = f.avg_pkt_size + (rand() % 10 - 5);
    o << std::fixed << std::setprecision(6)
      << t   << "," << step << "," << len << ","
      << (int)f.has_mqtt_port << ","
      << flag_syn << "," << flag_ack << "," << flag_fin << ","
      << flag_rst << "," << flag_psh << "," << flag_urg << ","
      << (int)f.to_mqtt << "," << (int)f.from_mqtt << "\n";
  }
}

// ════════════════════════════════════════════════════════════════════════════
//  PARSE DEFENDER RESULT JSON
// ════════════════════════════════════════════════════════════════════════════
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

// ════════════════════════════════════════════════════════════════════════════
//  ENFORCE DEFENDER ACTION (generic — takes broker/attacker app pointers)
// ════════════════════════════════════════════════════════════════════════════
static void EnforceDefenderAction(
    int action, bool attackDetected, int defId,
    DefState& ds,
    Ptr<MqttBrokerAppDef2> brokerApp,
    Ptr<MqttAttackAppDef2> attackApp,
    Ipv4Address attackerIP,
    Ptr<Node> brokerNode)
{
  NS_LOG_INFO("[DEFENDER" << defId << " t=" << Simulator::Now().GetSeconds() << "s] "
    << "Action=" << action << " (" << DEF_ACTION_NAMES[action] << ")"
    << "  det_prob=" << std::fixed << std::setprecision(3) << ds.lastDetProb
    << (attackDetected ? "  *** ATTACK MITIGATED ***" : ""));

  ds.actions[action]++;
  ds.lastAction = action;

  bool shouldBlock = (action==2||action==3||action==4||
                      action==5||action==9||action==10||action==11);
  bool shouldThrottle = (action==1||action==6||action==7||
                         action==8||action==12);
  bool shouldRelease  = (action==0||action==15);

  if(shouldBlock && !ds.blocked){
    ds.blocked = true;
    if(attackApp) attackApp->Suspend();
    if(brokerApp) brokerApp->BlockAttacker(attackerIP);
    NS_LOG_INFO("[DEFENDER" << defId << "] Attacker BLOCKED at broker.");
  }

  if(shouldThrottle && !ds.blocked){
    if(attackApp) attackApp->Suspend();
    double resumeAt = g_defEvalInterval / 2.0;
    // Capture ds.blocked by value to avoid dangling reference
    bool* blockedPtr = &ds.blocked;
    Simulator::Schedule(Seconds(resumeAt), [attackApp, blockedPtr](){
      if(attackApp && !(*blockedPtr)) attackApp->Resume();
    });
    NS_LOG_INFO("[DEFENDER" << defId << "] Attacker THROTTLED for " << resumeAt << "s.");
  }

  if(shouldRelease && ds.blocked){
    ds.blocked = false;
    if(attackApp) attackApp->Resume();
    NS_LOG_INFO("[DEFENDER" << defId << "] Block released — traffic allowed.");
  }

  if(action==14) ds.escLevel = std::min(ds.escLevel+1, 5);
  if(action==15) ds.escLevel = std::max(ds.escLevel-1, 0);

  // Update NetAnim broker colour
  if(g_anim && brokerNode){
    if(shouldBlock || ds.blocked){
      g_anim->UpdateNodeColor(brokerNode, 255, 165, 0);  // Orange = blocked
    } else if(action==0||action==13||action==15){
      g_anim->UpdateNodeColor(brokerNode, 34, 180, 100); // Green  = clear
    } else {
      g_anim->UpdateNodeColor(brokerNode, 255, 200, 0);  // Amber  = throttle
    }
  }
}

// ════════════════════════════════════════════════════════════════════════════
//  DEFENDER LOG FILES
// ════════════════════════════════════════════════════════════════════════════
static std::ofstream g_defLog0, g_defLog1;

static void WriteDefenderLogRow(std::ofstream& log, int defId,
    int action, double detProb, const DefState& ds, const NetFeatures& f){
  log << std::fixed << std::setprecision(4)
      << Simulator::Now().GetSeconds() << ","
      << defId  << ","
      << action << ","
      << DEF_ACTION_NAMES[action] << ","
      << detProb << ","
      << (int)ds.blocked << ","
      << ds.escLevel << ","
      << f.pkt_rate  << ","
      << f.byte_rate << ","
      << f.syn_ratio << ","
      << f.loss_ratio << "\n";
  log.flush();
}

// ════════════════════════════════════════════════════════════════════════════
//  DEFENDER EVAL CALLBACKS (one per LAN)
// ════════════════════════════════════════════════════════════════════════════
static void DefenderEval0();
static void DefenderEval1();

static void RunDefenderEval(
    int defId,
    Ipv4Address brokerIP, Ipv4Address attackerIP,
    DefState& ds,
    Ptr<MqttBrokerAppDef2> brokerApp,
    Ptr<MqttAttackAppDef2> attackApp,
    Ptr<Node> brokerNode,
    std::ofstream& defLog,
    void (*reschedule)())
{
  if(Simulator::Now().GetSeconds() > g_simTime) return;

  NetFeatures feats = ExtractFeatures(brokerIP);

  std::string idx       = std::to_string(defId);
  std::string queryPath = Out("defender_query_" + idx + ".csv");
  std::string resPath   = Out("defender_result_" + idx + ".json");
  WriteDefenderQuery(feats, queryPath);

  std::string cmd =
    "/home/ja/ns-allinone-3.46.1/ns-3.46.1/defender_env/bin/python3 "
    + DEFENDER_SCRIPT
    + " --query "    + queryPath
    + " --out "      + resPath
    + " --weights "  + DEFENDER_WEIGHTS_DIR
    + " --detector " + ACTIVE_DETECTOR
    + " 2>/dev/null";

  int ret = system(cmd.c_str());

  double detProb = 0.0;
  int    action  = 0;
  if(ret == 0){
    action = ParseDefenderResult(resPath, detProb);
  } else {
    detProb = feats.syn_ratio * 0.6 + feats.loss_ratio * 0.4;
    action  = (detProb > 0.6) ? 2 : (detProb > 0.35) ? 1 : 0;
    NS_LOG_WARN("[DEFENDER" << defId << "] Python bridge failed (ret="
      << ret << ") — fallback rule, action=" << action);
  }
  ds.lastDetProb  = detProb;

  bool attackDetected = (detProb >= 0.5);
  bool attackActive   = (Simulator::Now().GetSeconds() >= g_attackStart);

  if(attackActive && attackDetected)       ds.TP++;
  else if(attackActive && !attackDetected) ds.FN++;
  else if(!attackActive && attackDetected) ds.FP++;
  else                                     ds.TN++;

  EnforceDefenderAction(action, attackDetected, defId, ds,
                         brokerApp, attackApp, attackerIP, brokerNode);

  WriteDefenderLogRow(defLog, defId, action, detProb, ds, feats);

  Simulator::Schedule(Seconds(g_defEvalInterval), reschedule);
}

// LAN 0 defender
static Ptr<Node> g_broker0Node, g_broker1Node;

static void DefenderEval0(){
  RunDefenderEval(0,
    g_broker0IP, g_atk0IP, g_def0,
    g_brokerApp0, g_attackApp0,
    g_broker0Node, g_defLog0,
    &DefenderEval0);
}
static void DefenderEval1(){
  RunDefenderEval(1,
    g_broker1IP, g_atk1IP, g_def1,
    g_brokerApp1, g_attackApp1,
    g_broker1Node, g_defLog1,
    &DefenderEval1);
}

// ════════════════════════════════════════════════════════════════════════════
//  ATTACKER EVAL (per-broker)
// ════════════════════════════════════════════════════════════════════════════
static double GetLossForAttacker(Ipv4Address atkIP){
  if(!g_mon||!g_cls) return 0.5;
  g_mon->CheckForLostPackets();
  uint64_t tx=0,lost=0;
  for(auto &kv:g_mon->GetFlowStats()){
    auto t=g_cls->FindFlow(kv.first);
    if(t.sourceAddress==atkIP&&t.destinationPort==MQTT_PORT){
      tx+=kv.second.txPackets; lost+=kv.second.lostPackets;
    }
  }
  return tx>0?(double)lost/tx:0.5;
}

static void RLEval0(){
  double now=Simulator::Now().GetSeconds();
  if(now>=g_simTime-1.0) return;
  double loss=GetLossForAttacker(g_atk0IP);
  double rew=1.0-2.0*loss; if(g_rl0.mode==4) rew+=0.15;
  if(g_def0.blocked) rew-=3.0;  // penalty when defender is actively blocking
  int prev=g_rl0.mode;
  double bestQ=g_rl0.q[0];
  for(int i=1;i<N_MODES;i++) if(g_rl0.q[i]>bestQ) bestQ=g_rl0.q[i];
  g_rl0.q[prev]+=LR*(rew+GAMMA*bestQ-g_rl0.q[prev]);
  g_rl0.eps=std::max(EPS_FLOOR,g_rl0.eps*EPS_DECAY);
  int next;
  Ptr<UniformRandomVariable> u=CreateObject<UniformRandomVariable>();
  if(u->GetValue(0,1)<g_rl0.eps) next=(int)u->GetValue(0,N_MODES);
  else { next=0; for(int i=1;i<N_MODES;i++) if(g_rl0.q[i]>g_rl0.q[next]) next=i; }
  g_rl0.mU[prev]++;
  if(next!=prev&&g_rl0.app) g_rl0.app->SetMode(next);
  g_rl0.mode=next; g_rl0.steps++;
  NS_LOG_INFO("[ATK0 t="<<std::fixed<<std::setprecision(1)<<now<<"s]"
    <<" "<<ATK[prev].shortName<<" → "<<ATK[next].shortName
    <<" rew="<<std::setprecision(2)<<rew<<" eps="<<g_rl0.eps
    <<" blocked="<<g_def0.blocked);
  Simulator::Schedule(Seconds(g_evalInterval),&RLEval0);
}

static void RLEval1(){
  double now=Simulator::Now().GetSeconds();
  if(now>=g_simTime-1.0) return;
  double loss=GetLossForAttacker(g_atk1IP);
  double rew=1.0-2.0*loss; if(g_rl1.mode==4) rew+=0.15;
  if(g_def1.blocked) rew-=3.0;
  int prev=g_rl1.mode;
  double bestQ=g_rl1.q[0];
  for(int i=1;i<N_MODES;i++) if(g_rl1.q[i]>bestQ) bestQ=g_rl1.q[i];
  g_rl1.q[prev]+=LR*(rew+GAMMA*bestQ-g_rl1.q[prev]);
  g_rl1.eps=std::max(EPS_FLOOR,g_rl1.eps*EPS_DECAY);
  int next;
  Ptr<UniformRandomVariable> u=CreateObject<UniformRandomVariable>();
  if(u->GetValue(0,1)<g_rl1.eps) next=(int)u->GetValue(0,N_MODES);
  else { next=0; for(int i=1;i<N_MODES;i++) if(g_rl1.q[i]>g_rl1.q[next]) next=i; }
  g_rl1.mU[prev]++;
  if(next!=prev&&g_rl1.app) g_rl1.app->SetMode(next);
  g_rl1.mode=next; g_rl1.steps++;
  NS_LOG_INFO("[ATK1 t="<<std::fixed<<std::setprecision(1)<<now<<"s]"
    <<" "<<ATK[prev].shortName<<" → "<<ATK[next].shortName
    <<" rew="<<std::setprecision(2)<<rew<<" eps="<<g_rl1.eps
    <<" blocked="<<g_def1.blocked);
  Simulator::Schedule(Seconds(g_evalInterval),&RLEval1);
}

// ════════════════════════════════════════════════════════════════════════════
//  TIMESERIES SNAPSHOT
// ════════════════════════════════════════════════════════════════════════════
static std::ofstream g_tsFile;

struct TsEntry2 { double t; uint64_t sB,a0B,a1B; };
static std::vector<TsEntry2> g_ts;
static uint64_t g_pS=0, g_p0=0, g_p1=0;

static void SnapTS(){
  if(!g_mon||!g_cls) return;
  g_mon->CheckForLostPackets();
  uint64_t sB=0,a0B=0,a1B=0;
  for(auto &kv:g_mon->GetFlowStats()){
    auto t=g_cls->FindFlow(kv.first);
    if(t.sourceAddress==g_atk0IP)      a0B+=kv.second.txBytes;
    else if(t.sourceAddress==g_atk1IP) a1B+=kv.second.txBytes;
    else                               sB +=kv.second.txBytes;
  }
  double now=Simulator::Now().GetSeconds();
  g_tsFile<<std::fixed<<std::setprecision(1)<<now<<","
    <<(sB-g_pS)<<","<<(a0B-g_p0)<<","<<(a1B-g_p1)<<","
    <<std::setprecision(2)<<(sB-g_pS)*8.0/1000<<","
    <<(a0B-g_p0)*8.0/1000<<","<<(a1B-g_p1)*8.0/1000<<","
    <<g_def0.lastAction<<","<<DEF_ACTION_NAMES[g_def0.lastAction]<<","
    <<g_def0.lastDetProb<<","<<(int)g_def0.blocked<<","
    <<g_def1.lastAction<<","<<DEF_ACTION_NAMES[g_def1.lastAction]<<","
    <<g_def1.lastDetProb<<","<<(int)g_def1.blocked<<"\n";
  g_tsFile.flush();
  g_pS=sB; g_p0=a0B; g_p1=a1B;
  if(now<g_simTime-0.5)
    Simulator::Schedule(Seconds(1.0),&SnapTS);
}

// ════════════════════════════════════════════════════════════════════════════
//  OUTPUT CSVs
// ════════════════════════════════════════════════════════════════════════════
static void WriteFlowsCsv(){
  std::ofstream f(Out("flows.csv"));
  f<<"flow_id,src_ip,src_port,dst_ip,dst_port,proto,"
   <<"tx_pkts,tx_bytes,rx_pkts,rx_bytes,lost_pkts,"
   <<"delay_sum_ns,jitter_sum_ns,traffic_type\n";
  for(auto &kv:g_mon->GetFlowStats()){
    auto ft=g_cls->FindFlow(kv.first);
    auto &s=kv.second;
    std::string type="sensor";
    if(ft.sourceAddress==g_atk0IP) type="attack_b0";
    else if(ft.sourceAddress==g_atk1IP) type="attack_b1";
    f<<kv.first<<","
     <<ft.sourceAddress<<","<<ft.sourcePort<<","
     <<ft.destinationAddress<<","<<ft.destinationPort<<","
     <<(int)ft.protocol<<","
     <<s.txPackets<<","<<s.txBytes<<","
     <<s.rxPackets<<","<<s.rxBytes<<","
     <<s.lostPackets<<","
     <<s.delaySum.GetNanoSeconds()<<","
     <<s.jitterSum.GetNanoSeconds()<<","
     <<type<<"\n";
  }
}

static void WriteSumCsv(){
  std::ofstream f(Out("summary.csv"));
  f<<"Section,Key,Value\n";
  f<<"Topology,Brokers,2\n";
  f<<"Topology,Sensors,15\n";
  f<<"Topology,Attackers,2\n";
  f<<"Topology,Defenders,2\n";
  f<<"Simulation,SimTime,"<<g_simTime<<"\n";
  f<<"Simulation,AttackStart,"<<g_attackStart<<"\n";
  f<<"Simulation,DefEvalInterval,"<<g_defEvalInterval<<"\n";
  f<<"Defender,ActiveModel,"<<ACTIVE_DETECTOR<<"\n";
  // Defender 0
  f<<"Defender0,LastAction,"<<g_def0.lastAction<<"\n";
  f<<"Defender0,TP,"<<g_def0.TP<<"\n";
  f<<"Defender0,FP,"<<g_def0.FP<<"\n";
  f<<"Defender0,TN,"<<g_def0.TN<<"\n";
  f<<"Defender0,FN,"<<g_def0.FN<<"\n";
  double tpr0=(g_def0.TP+g_def0.FN)>0?(double)g_def0.TP/(g_def0.TP+g_def0.FN):0.0;
  double fpr0=(g_def0.FP+g_def0.TN)>0?(double)g_def0.FP/(g_def0.FP+g_def0.TN):0.0;
  f<<"Defender0,TPR,"<<std::fixed<<std::setprecision(4)<<tpr0<<"\n";
  f<<"Defender0,FPR,"<<std::setprecision(4)<<fpr0<<"\n";
  // Defender 1
  f<<"Defender1,LastAction,"<<g_def1.lastAction<<"\n";
  f<<"Defender1,TP,"<<g_def1.TP<<"\n";
  f<<"Defender1,FP,"<<g_def1.FP<<"\n";
  f<<"Defender1,TN,"<<g_def1.TN<<"\n";
  f<<"Defender1,FN,"<<g_def1.FN<<"\n";
  double tpr1=(g_def1.TP+g_def1.FN)>0?(double)g_def1.TP/(g_def1.TP+g_def1.FN):0.0;
  double fpr1=(g_def1.FP+g_def1.TN)>0?(double)g_def1.FP/(g_def1.FP+g_def1.TN):0.0;
  f<<"Defender1,TPR,"<<std::setprecision(4)<<tpr1<<"\n";
  f<<"Defender1,FPR,"<<std::setprecision(4)<<fpr1<<"\n";
  // Attackers
  for(int m=0;m<N_MODES;m++){
    f<<"Attacker0,Q_"<<ATK[m].shortName<<","<<std::setprecision(4)<<g_rl0.q[m]<<"\n";
    f<<"Attacker1,Q_"<<ATK[m].shortName<<","<<g_rl1.q[m]<<"\n";
  }
  f<<"Attacker0,Steps,"<<g_rl0.steps<<"\n";
  f<<"Attacker1,Steps,"<<g_rl1.steps<<"\n";
}

static void WriteRLLogCsv(){
  std::ofstream f(Out("rl_log.csv"));
  f<<"broker,steps,mode,mode_name,epsilon,q0,q1,q2,q3,q4\n";
  auto wr=[&](int bid, const RLState2& rl){
    f<<bid<<","<<rl.steps<<","<<rl.mode<<","<<ATK[rl.mode].shortName<<","
     <<std::fixed<<std::setprecision(4)<<rl.eps<<","
     <<rl.q[0]<<","<<rl.q[1]<<","<<rl.q[2]<<","<<rl.q[3]<<","<<rl.q[4]<<"\n";
  };
  wr(0,g_rl0); wr(1,g_rl1);
}

// ════════════════════════════════════════════════════════════════════════════
//  MAIN
// ════════════════════════════════════════════════════════════════════════════
int main(int argc, char *argv[])
{
  CommandLine cmd(__FILE__);
  cmd.AddValue("simTime",      "Simulation time (s)",       g_simTime);
  cmd.AddValue("attackStart",  "Attack start time (s)",     g_attackStart);
  cmd.AddValue("evalInterval", "Attacker eval interval (s)",  g_evalInterval);
  cmd.AddValue("defInterval",  "Defender eval interval (s)",g_defEvalInterval);
  cmd.AddValue("epsilon",      "Initial epsilon",        g_epsilon);
  cmd.AddValue("seed",         "Random seed",               g_seed);
  cmd.AddValue("outDir",       "Output directory",          g_outDir);
  cmd.AddValue("weightsDir",   "Defender weights dir",      DEFENDER_WEIGHTS_DIR);
  cmd.AddValue("defScript",    "Defender Python script",    DEFENDER_SCRIPT);
  cmd.AddValue("detector",     "Detector type",             ACTIVE_DETECTOR);
  cmd.Parse(argc, argv);

  Time::SetResolution(Time::NS);
  RngSeedManager::SetSeed(g_seed);
  LogComponentEnable("MqttDefended2Broker", LOG_LEVEL_INFO);
  srand(g_seed);

  MkDir(g_outDir); MkDir(g_outDir+"/pcap");

  // ── Open log files ─────────────────────────────────────────────────────────
  g_defLog0.open(Out("defender_log_0.csv"));
  g_defLog0<<"time_s,def_id,action_id,action_name,det_prob,blocked,"
            <<"esc_level,pkt_rate,byte_rate,syn_ratio,loss_ratio\n";

  g_defLog1.open(Out("defender_log_1.csv"));
  g_defLog1<<"time_s,def_id,action_id,action_name,det_prob,blocked,"
            <<"esc_level,pkt_rate,byte_rate,syn_ratio,loss_ratio\n";

  g_tsFile.open(Out("timeseries.csv"));
  g_tsFile<<"time_s,sensor_bytes,atk0_bytes,atk1_bytes,"
           <<"sensor_kbps,atk0_kbps,atk1_kbps,"
           <<"def0_action,def0_action_name,def0_det_prob,def0_blocked,"
           <<"def1_action,def1_action_name,def1_det_prob,def1_blocked\n";

  // ── Nodes ──────────────────────────────────────────────────────────────────
  // LAN 0: broker0 + 8 sensors + attacker0 + defender0
  NodeContainer lan0_brokers;   lan0_brokers.Create(1);   // Node 0
  NodeContainer lan0_sensors;   lan0_sensors.Create(8);   // Nodes 1-8
  NodeContainer lan0_atk;       lan0_atk.Create(1);       // Node 9
  NodeContainer lan0_def;       lan0_def.Create(1);       // Node 10
  // LAN 1: broker1 + 7 sensors + attacker1 + defender1
  NodeContainer lan1_brokers;   lan1_brokers.Create(1);   // Node 11
  NodeContainer lan1_sensors;   lan1_sensors.Create(7);   // Nodes 12-18
  NodeContainer lan1_atk;       lan1_atk.Create(1);       // Node 19
  NodeContainer lan1_def;       lan1_def.Create(1);       // Node 20

  NodeContainer lan0_all;
  lan0_all.Add(lan0_brokers); lan0_all.Add(lan0_sensors);
  lan0_all.Add(lan0_atk);     lan0_all.Add(lan0_def);

  NodeContainer lan1_all;
  lan1_all.Add(lan1_brokers); lan1_all.Add(lan1_sensors);
  lan1_all.Add(lan1_atk);     lan1_all.Add(lan1_def);

  g_broker0Node = lan0_brokers.Get(0);
  g_broker1Node = lan1_brokers.Get(0);

  // ── Mobility ───────────────────────────────────────────────────────────────
  MobilityHelper mob;
  mob.SetMobilityModel("ns3::ConstantPositionMobilityModel");

  // LAN 0 — left half (centred at x=50)
  {
    Ptr<ListPositionAllocator> p=CreateObject<ListPositionAllocator>();
    p->Add(Vector(50,50,0));    // Broker 0
    for(int i=0;i<8;i++){
      double angle=i*(2.0*M_PI/8.0)-(M_PI/2.0);
      p->Add(Vector(50+32*cos(angle), 50+32*sin(angle), 0));
    }
    p->Add(Vector(50,92,0));    // Attacker 0
    p->Add(Vector(85,50,0));    // Defender 0
    mob.SetPositionAllocator(p);
    mob.Install(lan0_all);
  }
  // LAN 1 — right half (centred at x=150)
  {
    Ptr<ListPositionAllocator> p=CreateObject<ListPositionAllocator>();
    p->Add(Vector(150,50,0));   // Broker 1
    for(int i=0;i<7;i++){
      double angle=i*(2.0*M_PI/7.0)-(M_PI/2.0);
      p->Add(Vector(150+32*cos(angle), 50+32*sin(angle), 0));
    }
    p->Add(Vector(150,92,0));   // Attacker 1
    p->Add(Vector(185,50,0));   // Defender 1
    mob.SetPositionAllocator(p);
    mob.Install(lan1_all);
  }

  // ── WiFi — two INDEPENDENT channels, one per LAN ──────────────────────────
  // Each LAN must have its own YansWifiChannel so NS-3 does not treat them
  // as a single broadcast domain (which would cause routing aborts).
  YansWifiChannelHelper chHelper = YansWifiChannelHelper::Default();

  YansWifiPhyHelper phy0;
  phy0.SetChannel(chHelper.Create());   // channel for LAN 0
  NetDeviceContainer devs0 = WNet(lan0_all, "mqtt-lan0-def", phy0);

  YansWifiPhyHelper phy1;
  phy1.SetChannel(chHelper.Create());   // channel for LAN 1 (different object)
  NetDeviceContainer devs1 = WNet(lan1_all, "mqtt-lan1-def", phy1);

  phy0.EnablePcap(g_outDir+"/pcap/broker0",   devs0.Get(0), true);
  phy0.EnablePcap(g_outDir+"/pcap/attacker0", devs0.Get(9), true);
  phy0.EnablePcap(g_outDir+"/pcap/defender0", devs0.Get(10),true);
  phy1.EnablePcap(g_outDir+"/pcap/broker1",   devs1.Get(0), true);
  phy1.EnablePcap(g_outDir+"/pcap/attacker1", devs1.Get(8), true);
  phy1.EnablePcap(g_outDir+"/pcap/defender1", devs1.Get(9), true);

  // ── Internet stack ─────────────────────────────────────────────────────────
  InternetStackHelper stack;
  stack.Install(lan0_all);
  stack.Install(lan1_all);

  Ipv4AddressHelper ip4;
  ip4.SetBase("10.0.0.0","255.255.255.0");
  Ipv4InterfaceContainer ifc0=ip4.Assign(devs0);
  ip4.SetBase("10.1.0.0","255.255.255.0");
  Ipv4InterfaceContainer ifc1=ip4.Assign(devs1);
  // Do NOT use Ipv4GlobalRoutingHelper here — it aborts when two independent
  // ad-hoc WiFi LANs share the same broadcast channel object.
  // Each LAN is self-contained (nodes only talk within their /24 subnet),
  // so no routing helper is needed at all.

  // LAN 0 addresses: broker=.1, sensors=.2-.9, atk=.10, def=.11
  g_broker0IP = ifc0.GetAddress(0);   // 10.0.0.1
  g_atk0IP    = ifc0.GetAddress(9);   // 10.0.0.10
  g_def0IP    = ifc0.GetAddress(10);  // 10.0.0.11

  // LAN 1 addresses: broker=.1, sensors=.2-.8, atk=.9, def=.10
  g_broker1IP = ifc1.GetAddress(0);   // 10.1.0.1
  g_atk1IP    = ifc1.GetAddress(8);   // 10.1.0.9
  g_def1IP    = ifc1.GetAddress(9);   // 10.1.0.10

  NS_LOG_INFO("Broker0="<<g_broker0IP
    <<"  Attacker0="<<g_atk0IP<<"  Defender0="<<g_def0IP);
  NS_LOG_INFO("Broker1="<<g_broker1IP
    <<"  Attacker1="<<g_atk1IP<<"  Defender1="<<g_def1IP);

  // ── Broker apps ────────────────────────────────────────────────────────────
  {
    g_brokerApp0=CreateObject<MqttBrokerAppDef2>();
    g_brokerApp0->Setup(MQTT_PORT);
    lan0_brokers.Get(0)->AddApplication(g_brokerApp0);
    g_brokerApp0->SetStartTime(Seconds(0.5));
    g_brokerApp0->SetStopTime(Seconds(g_simTime));
  }
  {
    g_brokerApp1=CreateObject<MqttBrokerAppDef2>();
    g_brokerApp1->Setup(MQTT_PORT);
    lan1_brokers.Get(0)->AddApplication(g_brokerApp1);
    g_brokerApp1->SetStartTime(Seconds(0.5));
    g_brokerApp1->SetStopTime(Seconds(g_simTime));
  }

  // ── Sensor apps — LAN 0 (8 sensors) ────────────────────────────────────────
  struct SCfg { const char *topic; double interval; };
  SCfg cfgs0[]={
    {"sensors/temperature_humidity",2.0},{"sensors/water_level",3.0},
    {"sensors/ultrasonic",1.0},          {"sensors/flame_ir",2.0},
    {"sensors/motion",1.0},              {"sensors/light",2.0},
    {"sensors/gas",4.0},                 {"sensors/humid",2.5},
  };
  for(int i=0;i<8;i++){
    Ptr<MqttSensorAppDef2> a=CreateObject<MqttSensorAppDef2>();
    a->Setup(g_broker0IP,MQTT_PORT,"LAN0_S"+std::to_string(i),
             cfgs0[i].topic, cfgs0[i].interval, g_simTime);
    lan0_sensors.Get(i)->AddApplication(a);
    a->SetStartTime(Seconds(1.0+i*0.1));
    a->SetStopTime(Seconds(g_simTime));
  }

  // ── Sensor apps — LAN 1 (7 sensors) ────────────────────────────────────────
  SCfg cfgs1[]={
    {"sensors/temperature_humidity",2.0},{"sensors/ultrasonic",1.0},
    {"sensors/flame_ir",2.0},            {"sensors/motion",1.0},
    {"sensors/light",2.0},               {"sensors/gas",4.0},
    {"sensors/humid",2.5},
  };
  for(int i=0;i<7;i++){
    Ptr<MqttSensorAppDef2> a=CreateObject<MqttSensorAppDef2>();
    a->Setup(g_broker1IP,MQTT_PORT,"LAN1_S"+std::to_string(i),
             cfgs1[i].topic, cfgs1[i].interval, g_simTime);
    lan1_sensors.Get(i)->AddApplication(a);
    a->SetStartTime(Seconds(1.0+i*0.1));
    a->SetStopTime(Seconds(g_simTime));
  }

  // ── Attack apps ─────────────────────────────────────────────────────────────
  g_rl0.mode=0; g_rl1.mode=0;
  {
    g_attackApp0=CreateObject<MqttAttackAppDef2>();
    g_attackApp0->Setup(g_broker0IP,MQTT_PORT,0,g_simTime,0);
    lan0_atk.Get(0)->AddApplication(g_attackApp0);
    g_attackApp0->SetStartTime(Seconds(g_attackStart));
    g_attackApp0->SetStopTime(Seconds(g_simTime));
    g_rl0.app=g_attackApp0;
  }
  {
    g_attackApp1=CreateObject<MqttAttackAppDef2>();
    g_attackApp1->Setup(g_broker1IP,MQTT_PORT,0,g_simTime,1);
    lan1_atk.Get(0)->AddApplication(g_attackApp1);
    g_attackApp1->SetStartTime(Seconds(g_attackStart+2.0)); // staggered
    g_attackApp1->SetStopTime(Seconds(g_simTime));
    g_rl1.app=g_attackApp1;
  }

  // ── FlowMonitor ─────────────────────────────────────────────────────────────
  FlowMonitorHelper fmh;
  g_mon=fmh.InstallAll();
  g_cls=DynamicCast<Ipv4FlowClassifier>(fmh.GetClassifier());

  // ── Schedule ────────────────────────────────────────────────────────────────
  // Attackers (staggered 2 s apart)
  Simulator::Schedule(Seconds(g_attackStart+g_evalInterval),   &RLEval0);
  Simulator::Schedule(Seconds(g_attackStart+g_evalInterval+2.0),&RLEval1);
  // Defenders (start 4 s after attack, staggered 2 s to avoid simultaneous Python calls)
  Simulator::Schedule(Seconds(g_attackStart+g_defEvalInterval),         &DefenderEval0);
  Simulator::Schedule(Seconds(g_attackStart+g_defEvalInterval+2.0),     &DefenderEval1);
  // Timeseries snapshot every second
  Simulator::Schedule(Seconds(1.0),&SnapTS);

  // ── NetAnim ──────────────────────────────────────────────────────────────────
  std::string animFile=Out("mqtt-2broker-defended-anim.xml");
  AnimationInterface anim(animFile);
  g_anim=&anim;

  // Broker 0
  anim.SetConstantPosition(lan0_brokers.Get(0),50.0,50.0);
  anim.UpdateNodeDescription(lan0_brokers.Get(0),
    "MQTT BROKER 0\n10.0.0.1 | :1883\n[AI Defended]");
  anim.UpdateNodeColor(lan0_brokers.Get(0),34,180,100);
  anim.UpdateNodeSize(lan0_brokers.Get(0)->GetId(),5.5,5.5);

  // Broker 1
  anim.SetConstantPosition(lan1_brokers.Get(0),150.0,50.0);
  anim.UpdateNodeDescription(lan1_brokers.Get(0),
    "MQTT BROKER 1\n10.1.0.1 | :1883\n[AI Defended]");
  anim.UpdateNodeColor(lan1_brokers.Get(0),34,180,100);
  anim.UpdateNodeSize(lan1_brokers.Get(0)->GetId(),5.5,5.5);

  // Sensors LAN 0
  const char* sLabel0[]={"Temp/Humid","WaterLevel","Ultrasonic","FlameIR",
                          "Motion","Light","Gas","Humid"};
  for(int i=0;i<8;i++){
    double angle=i*(2.0*M_PI/8.0)-(M_PI/2.0);
    anim.SetConstantPosition(lan0_sensors.Get(i),
      50.0+32.0*cos(angle), 50.0+32.0*sin(angle));
    anim.UpdateNodeDescription(lan0_sensors.Get(i),
      std::string("S")+std::to_string(i+1)+":"+sLabel0[i]+"\nLAN0");
    anim.UpdateNodeColor(lan0_sensors.Get(i),70,130,255);
    anim.UpdateNodeSize(lan0_sensors.Get(i)->GetId(),3.5,3.5);
  }

  // Sensors LAN 1
  const char* sLabel1[]={"Temp/Humid","Ultrasonic","FlameIR",
                          "Motion","Light","Gas","Humid"};
  for(int i=0;i<7;i++){
    double angle=i*(2.0*M_PI/7.0)-(M_PI/2.0);
    anim.SetConstantPosition(lan1_sensors.Get(i),
      150.0+32.0*cos(angle), 50.0+32.0*sin(angle));
    anim.UpdateNodeDescription(lan1_sensors.Get(i),
      std::string("S")+std::to_string(i+9)+":"+sLabel1[i]+"\nLAN1");
    anim.UpdateNodeColor(lan1_sensors.Get(i),70,130,255);
    anim.UpdateNodeSize(lan1_sensors.Get(i)->GetId(),3.5,3.5);
  }

  // Attacker 0
  anim.SetConstantPosition(lan0_atk.Get(0),50.0,92.0);
  anim.UpdateNodeDescription(lan0_atk.Get(0),
    "! ATTACKER 0 !\n10.0.0.10 | DDoS\nTargets Broker 0");
  anim.UpdateNodeColor(lan0_atk.Get(0),220,40,40);
  anim.UpdateNodeSize(lan0_atk.Get(0)->GetId(),4.5,4.5);

  // Attacker 1
  anim.SetConstantPosition(lan1_atk.Get(0),150.0,92.0);
  anim.UpdateNodeDescription(lan1_atk.Get(0),
    "! ATTACKER 1 !\n10.1.0.9 | DDoS\nTargets Broker 1");
  anim.UpdateNodeColor(lan1_atk.Get(0),220,40,40);
  anim.UpdateNodeSize(lan1_atk.Get(0)->GetId(),4.5,4.5);

  // Defender 0
  anim.SetConstantPosition(lan0_def.Get(0),85.0,50.0);
  anim.UpdateNodeDescription(lan0_def.Get(0),
    "AI DEFENDER 0\n10.0.0.11\nCNN-BiLSTM-Attn");
  anim.UpdateNodeColor(lan0_def.Get(0),148,0,211);  // purple
  anim.UpdateNodeSize(lan0_def.Get(0)->GetId(),4.5,4.5);

  // Defender 1
  anim.SetConstantPosition(lan1_def.Get(0),185.0,50.0);
  anim.UpdateNodeDescription(lan1_def.Get(0),
    "AI DEFENDER 1\n10.1.0.10\nCNN-BiLSTM-Attn");
  anim.UpdateNodeColor(lan1_def.Get(0),148,0,211);  // purple
  anim.UpdateNodeSize(lan1_def.Get(0)->GetId(),4.5,4.5);

  anim.EnablePacketMetadata(true);
  NS_LOG_INFO("NetAnim → "<<animFile);

  // ── Run ──────────────────────────────────────────────────────────────────────
  Simulator::Stop(Seconds(g_simTime+1.0));
  NS_LOG_INFO("=== MQTT 2-Broker AI-Defended Simulation Starting ===");
  NS_LOG_INFO("2 Brokers | 15 Sensors | 2 Attackers | 2 AI Defenders");
  NS_LOG_INFO("Detector: "<<ACTIVE_DETECTOR
    <<"  AttackStart="<<g_attackStart<<"s"
    <<"  DefInterval="<<g_defEvalInterval<<"s");
  Simulator::Run();

  // ── Outputs ──────────────────────────────────────────────────────────────────
  g_mon->CheckForLostPackets();
  g_mon->SerializeToXmlFile(Out("mqtt-2broker-defended-flowmonitor.xml"),true,true);
  WriteFlowsCsv();
  WriteSumCsv();
  WriteRLLogCsv();
  g_defLog0.close();
  g_defLog1.close();
  g_tsFile.close();

  double tpr0=(g_def0.TP+g_def0.FN)>0?100.0*g_def0.TP/(g_def0.TP+g_def0.FN):0.0;
  double fpr0=(g_def0.FP+g_def0.TN)>0?100.0*g_def0.FP/(g_def0.FP+g_def0.TN):0.0;
  double tpr1=(g_def1.TP+g_def1.FN)>0?100.0*g_def1.TP/(g_def1.TP+g_def1.FN):0.0;
  double fpr1=(g_def1.FP+g_def1.TN)>0?100.0*g_def1.FP/(g_def1.FP+g_def1.TN):0.0;

  std::cout<<"\n╔══════════════════════════════════════════════════════════╗\n";
  std::cout<<"║  MQTT 2-Broker AI-Defended Simulation — Complete        ║\n";
  std::cout<<"╚══════════════════════════════════════════════════════════╝\n\n";
  std::cout<<"  Topology  : 2 Brokers + 15 Sensors + 2 Attackers + 2 AI Defenders\n";
  std::cout<<"  Detector  : "<<ACTIVE_DETECTOR<<"\n\n";
  std::cout<<"  DEFENDER 0 (LAN 0):\n";
  std::cout<<"    TP="<<g_def0.TP<<"  FP="<<g_def0.FP
           <<"  TN="<<g_def0.TN<<"  FN="<<g_def0.FN<<"\n";
  std::cout<<"    TPR="<<std::fixed<<std::setprecision(1)<<tpr0<<"%"
           <<"   FPR="<<fpr0<<"%\n\n";
  std::cout<<"  DEFENDER 1 (LAN 1):\n";
  std::cout<<"    TP="<<g_def1.TP<<"  FP="<<g_def1.FP
           <<"  TN="<<g_def1.TN<<"  FN="<<g_def1.FN<<"\n";
  std::cout<<"    TPR="<<std::setprecision(1)<<tpr1<<"%"
           <<"   FPR="<<fpr1<<"%\n\n";
  std::cout<<"  ATTACKER 0 Q-TABLE:\n";
  for(int m=0;m<N_MODES;m++)
    std::cout<<"    ["<<m<<"] "<<std::setw(8)<<ATK[m].shortName
             <<"  Q="<<std::fixed<<std::setprecision(3)<<g_rl0.q[m]
             <<"  used="<<(int)g_rl0.mU[m]<<"\n";
  std::cout<<"  ATTACKER 1 Q-TABLE:\n";
  for(int m=0;m<N_MODES;m++)
    std::cout<<"    ["<<m<<"] "<<std::setw(8)<<ATK[m].shortName
             <<"  Q="<<std::fixed<<std::setprecision(3)<<g_rl1.q[m]
             <<"  used="<<(int)g_rl1.mU[m]<<"\n";
  std::cout<<"  Output → "<<g_outDir<<"/\n";
  std::cout<<"  NetAnim → open: "<<animFile<<"\n\n";

  Simulator::Destroy();
  NS_LOG_INFO("Done.");
  return 0;
}
