/* =============================================================================
 * NS-3 MQTT DDoS RL Simulation — 1 Broker, 6 Sensors, 1 Attacker
 * =============================================================================
 *
 * TOPOLOGY  (Wireless 802.11b Ad-Hoc, 10.0.0.0/24)
 *
 *   Node  IP           Role
 *   ────  ───────────  ──────────────────────────────────────
 *     0   10.0.0.1     MQTT Broker (TCP:1883)
 *     1   10.0.0.2     Sensor 1 — Temperature & Humidity  (DHT22)
 *     2   10.0.0.3     Sensor 2 — Water Level             (HC-SR04 flood)
 *     3   10.0.0.4     Sensor 3 — Ultrasonic Distance     (HC-SR04)
 *     4   10.0.0.5     Sensor 4 — Flame / IR Detection    (KY-026)
 *     5   10.0.0.6     Sensor 5 — Motion Detection        (PIR HC-SR501)
 *     6   10.0.0.7     Sensor 6 — Light Intensity         (LDR / BH1750)
 *     7   10.0.0.8     ATTACKER  (RL-DDoS agent)
 *
 * ATTACK MODES (CTGAN-matched):
 *   0 SYN    — rapid TCP SYN flood                         delta=1.709s
 *   1 BASIC  — standard MQTT CONNECT flood                 delta=0.476s
 *   2 DELAY  — slow CONNECT, delay before payload          delta=0.890s
 *   3 INVSUB — MQTT SUBSCRIBE with invalid topic           delta=0.751s
 *   4 WILL   — MQTT CONNECT with large WILL payload        delta=0.490s
 *
 * RL: Q-table updated every evalInterval seconds via FlowMonitor loss ratio.
 *
 * OUTPUT → attack_1broker_output/
 *   pcap/  flows.csv  rl_log.csv  timeseries.csv  summary.csv
 *   mqtt-attack-anim.xml  mqtt-attack-flowmonitor.xml
 *
 * BUILD:
 *   cp mqtt_1broker_attack.cc $NS3_DIR/scratch/
 *   cd $NS3_DIR && ./ns3 run scratch/mqtt_1broker_attack
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
#include <sys/stat.h>

using namespace ns3;
NS_LOG_COMPONENT_DEFINE ("MqttAttack1Broker");

// ════════════════════════════════════════════════════════════
// PARAMETERS
// ════════════════════════════════════════════════════════════
static const uint16_t MQTT_PORT    = 1883;
static double      g_simTime       = 90.0;
static double      g_attackStart   = 10.0;
static double      g_evalInterval  = 8.0;
static double      g_epsilon       = 0.90;
static uint32_t    g_seed          = 42;
static std::string g_outDir        = "attack_1broker_output";

static const double EPS_DECAY=0.98, EPS_FLOOR=0.05, GAMMA=0.95, LR_RL=0.10;
static const int    N_MODES=5;

struct AtkProfile { const char *name,*shortName; uint32_t pktBytes; double delta; };
static const AtkProfile ATK[5]={
  {"SYN_TCP_Flooding",                   "SYN",    62,  1.709},
  {"Basic_Connect_Flooding",             "BASIC",  61,  0.476},
  {"Delayed_Connect_Flooding",           "DELAY",  62,  0.890},
  {"Invalid_Subscription_Flooding",      "INVSUB", 63,  0.751},
  {"Connect_Flooding_with_WILL_payload", "WILL",   162, 0.490}
};

static Ipv4Address g_brokerIP, g_attackerIP;
static Ptr<FlowMonitor>        g_mon;
static Ptr<Ipv4FlowClassifier> g_cls;

// ════════════════════════════════════════════════════════════
// MQTT FRAME BUILDER
// ════════════════════════════════════════════════════════════
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

// ════════════════════════════════════════════════════════════
// MqttBrokerApp
// ════════════════════════════════════════════════════════════
class MqttBrokerApp : public Application {
public:
  static TypeId GetTypeId(){
    static TypeId t=TypeId("MqttBrokerApp1A").SetParent<Application>()
      .SetGroupName("Tutorial").AddConstructor<MqttBrokerApp>(); return t;
  }
  void Setup(uint16_t port){ m_port=port; }
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
    for(auto &s:m_clients) s->Close(); m_clients.clear();
    if(m_sock){m_sock->Close();m_sock=nullptr;}
  }
  void OnAccept(Ptr<Socket> s,const Address&){
    m_clients.push_back(s);
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
  uint16_t                 m_port{MQTT_PORT};
};

// ════════════════════════════════════════════════════════════
// MqttSensorApp
// ════════════════════════════════════════════════════════════
class MqttSensorApp : public Application {
public:
  static TypeId GetTypeId(){
    static TypeId t=TypeId("MqttSensorApp1A").SetParent<Application>()
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
    m_sock->SetRecvCallback(MakeCallback(&MqttSensorApp::OnRecv,this));
    m_sock->Connect(InetSocketAddress(m_br,m_port));
  }
  void StopApplication() override {
    m_ev.Cancel();
    if(m_sock){m_sock->Close();m_sock=nullptr;}
  }
  void OnConn(Ptr<Socket> s){
    s->Send(Mqtt::ToPkt(Mqtt::Connect(m_cid)));
    Simulator::Schedule(MilliSeconds(150),&MqttSensorApp::DoPub,this);
  }
  void OnRecv(Ptr<Socket> s){ Ptr<Packet> p; while((p=s->Recv())){} }
  void DoPub(){
    if(!m_sock||Simulator::Now()>=m_stopAt) return;
    m_sock->Send(Mqtt::ToPkt(Mqtt::Publish(m_topic,Payload())));
    m_cnt++;
    m_ev=Simulator::Schedule(m_interval,&MqttSensorApp::DoPub,this);
  }
  std::string Payload(){
    std::ostringstream ss;
    if(m_topic=="sensors/temperature_humidity"){
      ss<<"T:"<<std::fixed<<std::setprecision(1)<<(22.0+(m_cnt%8)*0.5)
        <<" H:"<<std::setprecision(1)<<(55.0+(m_cnt%10)*0.8);
      return ss.str();
    }
    if(m_topic=="sensors/water_level")
      return (m_cnt%7==0)?"Level:High":"Level:Normal";
    if(m_topic=="sensors/ultrasonic"){
      ss<<std::fixed<<std::setprecision(3)<<(10.0+(m_cnt%20)*0.5)<<" cm";
      return ss.str();
    }
    if(m_topic=="sensors/flame_ir")
      return (m_cnt%15==0)?"Flame Detected!":"0";
    if(m_topic=="sensors/motion")
      return (m_cnt%3==0)?"Motion Detected!":"No Motion";
    if(m_topic=="sensors/light"){
      ss<<"Lux:"<<std::fixed<<std::setprecision(1)<<(100.0+(m_cnt%30)*8.5);
      return ss.str();
    }
    return "data";
  }
  Ptr<Socket> m_sock{nullptr};
  Ipv4Address m_br; uint16_t m_port{MQTT_PORT};
  std::string m_cid, m_topic;
  Time        m_interval, m_stopAt;
  EventId     m_ev;
  uint32_t    m_cnt{0};
};

// ════════════════════════════════════════════════════════════
// MqttAttackApp
// ════════════════════════════════════════════════════════════
class MqttAttackApp : public Application {
public:
  static TypeId GetTypeId(){
    static TypeId t=TypeId("MqttAttackApp1A").SetParent<Application>()
      .SetGroupName("Tutorial").AddConstructor<MqttAttackApp>(); return t;
  }
  void Setup(Ipv4Address tgt,uint16_t port,int mode,double stopTime){
    m_tgt=tgt; m_port=port; m_mode=mode; m_stopAt=Seconds(stopTime);
  }
  void SetMode(int m){ m_mode=m; }
  int  GetMode()const{ return m_mode; }
private:
  void StartApplication() override { SchedNext(); }
  void StopApplication()  override {
    m_ev.Cancel();
    for(auto &s:m_socks) s->Close(); m_socks.clear();
  }
  void SchedNext(){
    double d=ATK[m_mode].delta;
    Ptr<UniformRandomVariable> u=CreateObject<UniformRandomVariable>();
    d*=(0.8+u->GetValue(0.0,0.4));
    m_ev=Simulator::Schedule(Seconds(d),&MqttAttackApp::Fire,this);
  }
  void Fire(){
    if(Simulator::Now()>=m_stopAt) return;
    Ptr<Socket> s=Socket::CreateSocket(GetNode(),TcpSocketFactory::GetTypeId());
    m_socks.push_back(s);
    int mode=m_mode;
    s->SetConnectCallback(
      MakeBoundCallback(&MqttAttackApp::OnConn,this,mode),
      MakeNullCallback<void,Ptr<Socket>>());
    s->Connect(InetSocketAddress(m_tgt,m_port));
    SchedNext();
  }
  static void OnConn(MqttAttackApp*self,int mode,Ptr<Socket> s){
    std::vector<uint8_t> f;
    std::string rnd=std::to_string(rand()%65535);
    switch(mode){
      case 0: f=Mqtt::Connect("syn_"+rnd); break;
      case 1: f=Mqtt::Connect("flood_"+rnd); break;
      case 2:
        Simulator::Schedule(MilliSeconds(500),[s,rnd](){
          s->Send(Mqtt::ToPkt(Mqtt::Connect("delay_"+rnd)));
        }); return;
      case 3: f=Mqtt::Subscribe("invalid/##/bad_topic",rand()%65535); break;
      case 4: f=Mqtt::Connect("will_"+rnd,true,
                               "sensors/flame_ir",
                               "ALERT_"+std::to_string(rand()%1000)); break;
      default:f=Mqtt::Connect("atk_"+rnd); break;
    }
    s->Send(Mqtt::ToPkt(f));
  }
  Ipv4Address              m_tgt; uint16_t m_port{MQTT_PORT};
  int                      m_mode{0};
  Time                     m_stopAt;
  EventId                  m_ev;
  std::vector<Ptr<Socket>> m_socks;
};

// ════════════════════════════════════════════════════════════
// RL STATE
// ════════════════════════════════════════════════════════════
struct RLEntry{double t;int prev,next,step;double loss,rew,eps;double q[N_MODES];};
static std::vector<RLEntry> g_rlLog;
struct TsEntry{double t;uint64_t sB,aB;};
static std::vector<TsEntry> g_ts;
static uint64_t g_pS=0,g_pA=0;

struct RLState{
  int mode=0,steps=0;
  double q[N_MODES],eps,mU[N_MODES],mR[N_MODES];
  Ptr<MqttAttackApp> app;
  RLState():eps(g_epsilon){
    for(int i=0;i<N_MODES;i++){q[i]=0;mU[i]=0;mR[i]=0;}
  }
  int select(){
    Ptr<UniformRandomVariable> u=CreateObject<UniformRandomVariable>();
    if(u->GetValue(0,1)<eps)return(int)u->GetValue(0,N_MODES);
    int b=0;for(int i=1;i<N_MODES;i++)if(q[i]>q[b])b=i;return b;
  }
  void update(int m,double r){
    double bn=q[0];for(int i=1;i<N_MODES;i++)if(q[i]>bn)bn=q[i];
    q[m]+=LR_RL*(r+GAMMA*bn-q[m]);
    mU[m]++;mR[m]+=r;
    eps=std::max(EPS_FLOOR,eps*EPS_DECAY);steps++;
  }
} g_rl;

// ════════════════════════════════════════════════════════════
// HELPERS
// ════════════════════════════════════════════════════════════
void MkDir(const std::string &p){ mkdir(p.c_str(),0755); }
std::string Out(const std::string &f){ return g_outDir+"/"+f; }

NetDeviceContainer WNet(NodeContainer n,const std::string &ssid,YansWifiPhyHelper &phy){
  WifiHelper w; w.SetStandard(WIFI_STANDARD_80211b);
  w.SetRemoteStationManager("ns3::ConstantRateWifiManager",
    "DataMode",StringValue("DsssRate11Mbps"),
    "ControlMode",StringValue("DsssRate11Mbps"));
  WifiMacHelper mac; mac.SetType("ns3::AdhocWifiMac");
  return w.Install(phy,mac,n);
}

double GetLoss(){
  if(!g_mon||!g_cls)return 0.5;
  g_mon->CheckForLostPackets();
  uint64_t tx=0,lost=0;
  for(auto &f:g_mon->GetFlowStats()){
    auto t=g_cls->FindFlow(f.first);
    if(t.sourceAddress==g_attackerIP&&t.destinationPort==MQTT_PORT){
      tx+=f.second.txPackets;lost+=f.second.lostPackets;
    }
  }
  return tx>0?(double)lost/tx:0.5;
}

void RLEval(){
  double now=Simulator::Now().GetSeconds();
  if(now>=g_simTime-1.0)return;
  double loss=GetLoss();
  double rew=1.0-2.0*loss; if(g_rl.mode==4)rew+=0.15;
  int prev=g_rl.mode; g_rl.update(prev,rew); int next=g_rl.select();
  if(next!=prev&&g_rl.app) g_rl.app->SetMode(next);
  g_rl.mode=next;
  RLEntry e; e.t=now;e.prev=prev;e.next=next;e.loss=loss;
  e.rew=rew;e.eps=g_rl.eps;e.step=g_rl.steps;
  for(int i=0;i<N_MODES;i++)e.q[i]=g_rl.q[i];
  g_rlLog.push_back(e);
  NS_LOG_INFO("[RL] t="<<std::fixed<<std::setprecision(1)<<now
    <<"s step="<<g_rl.steps<<" loss="<<std::setprecision(3)<<loss
    <<" rew="<<std::setprecision(2)<<rew<<" eps="<<std::setprecision(3)<<g_rl.eps
    <<" "<<ATK[prev].shortName<<" -> "<<ATK[next].shortName);
  Simulator::Schedule(Seconds(g_evalInterval),&RLEval);
}

void SnapTS(){
  if(!g_mon||!g_cls)return;
  g_mon->CheckForLostPackets();
  auto st=g_mon->GetFlowStats();
  uint64_t sB=0,aB=0;
  for(auto &f:st){
    auto t=g_cls->FindFlow(f.first);
    bool isA=(t.sourceAddress==g_attackerIP);
    if(isA)aB+=f.second.txBytes; else sB+=f.second.txBytes;
  }
  g_ts.push_back({Simulator::Now().GetSeconds(),sB-g_pS,aB-g_pA});
  g_pS=sB; g_pA=aB;
  if(Simulator::Now().GetSeconds()<g_simTime-0.5)
    Simulator::Schedule(Seconds(1.0),&SnapTS);
}

void WriteFlowsCsv(){
  std::ofstream f(Out("flows.csv"));
  f<<"flow_id,src_ip,src_port,dst_ip,dst_port,tx_packets,rx_packets,"
   <<"lost_packets,loss_pct,avg_delay_ms,throughput_mbps,traffic_type\n";
  for(auto &fl:g_mon->GetFlowStats()){
    auto t=g_cls->FindFlow(fl.first);
    double lp=fl.second.txPackets>0?100.0*fl.second.lostPackets/fl.second.txPackets:0;
    double ad=fl.second.rxPackets>0?fl.second.delaySum.GetSeconds()/fl.second.rxPackets*1000:0;
    double tp=0;
    if(fl.second.timeLastRxPacket>fl.second.timeFirstTxPacket){
      double d=(fl.second.timeLastRxPacket-fl.second.timeFirstTxPacket).GetSeconds();
      tp=fl.second.rxBytes*8.0/d/1e6;
    }
    bool isA=(t.sourceAddress==g_attackerIP);
    f<<fl.first<<","<<t.sourceAddress<<","<<t.sourcePort<<","
     <<t.destinationAddress<<","<<t.destinationPort<<","
     <<fl.second.txPackets<<","<<fl.second.rxPackets<<","
     <<fl.second.lostPackets<<","
     <<std::fixed<<std::setprecision(2)<<lp<<","
     <<std::setprecision(3)<<ad<<","<<std::setprecision(6)<<tp<<","
     <<(isA?"attack":"sensor")<<"\n";
  }
  NS_LOG_INFO("Written: "<<Out("flows.csv"));
}

void WriteRLCsv(){
  std::ofstream f(Out("rl_log.csv"));
  f<<"time_s,step,prev_mode,prev_name,new_mode,new_name,"
   <<"loss_ratio,reward,epsilon,q0_SYN,q1_BASIC,q2_DELAY,q3_INVSUB,q4_WILL\n";
  for(auto &e:g_rlLog){
    f<<std::fixed<<std::setprecision(2)<<e.t<<","<<e.step<<","
     <<e.prev<<","<<ATK[e.prev].shortName<<","
     <<e.next<<","<<ATK[e.next].shortName<<","
     <<std::setprecision(4)<<e.loss<<","<<e.rew<<","<<e.eps<<","
     <<e.q[0]<<","<<e.q[1]<<","<<e.q[2]<<","<<e.q[3]<<","<<e.q[4]<<"\n";
  }
  NS_LOG_INFO("Written: "<<Out("rl_log.csv"));
}

void WriteTsCsv(){
  std::ofstream f(Out("timeseries.csv"));
  f<<"time_s,sensor_bytes,attack_bytes,sensor_kbps,attack_kbps\n";
  for(auto &e:g_ts){
    f<<std::fixed<<std::setprecision(1)<<e.t<<","<<e.sB<<","<<e.aB<<","
     <<std::setprecision(2)<<e.sB*8.0/1000<<","<<e.aB*8.0/1000<<"\n";
  }
  NS_LOG_INFO("Written: "<<Out("timeseries.csv"));
}

void WriteSumCsv(){
  auto st=g_mon->GetFlowStats();
  uint64_t sTx=0,sRx=0,sL=0,sTB=0,aTx=0,aRx=0,aL=0,aTB=0;
  for(auto &fl:st){
    auto t=g_cls->FindFlow(fl.first);
    bool isA=(t.sourceAddress==g_attackerIP);
    if(isA){aTx+=fl.second.txPackets;aRx+=fl.second.rxPackets;
            aL+=fl.second.lostPackets;aTB+=fl.second.txBytes;}
    else   {sTx+=fl.second.txPackets;sRx+=fl.second.rxPackets;
            sL+=fl.second.lostPackets;sTB+=fl.second.txBytes;}
  }
  auto pct=[](uint64_t l,uint64_t t)->double{return t>0?100.0*l/t:0;};
  std::ofstream f(Out("summary.csv"));
  f<<"category,tx_packets,rx_packets,lost_packets,loss_pct,tx_bytes\n";
  f<<"sensor,"<<sTx<<","<<sRx<<","<<sL<<","
   <<std::fixed<<std::setprecision(2)<<pct(sL,sTx)<<","<<sTB<<"\n";
  f<<"attack,"<<aTx<<","<<aRx<<","<<aL<<","<<pct(aL,aTx)<<","<<aTB<<"\n";
  f<<"\nRL Final State:\n";
  f<<"final_mode,final_name,steps,epsilon,q0,q1,q2,q3,q4\n";
  f<<g_rl.mode<<","<<ATK[g_rl.mode].shortName<<","<<g_rl.steps<<","
   <<std::setprecision(4)<<g_rl.eps<<","
   <<g_rl.q[0]<<","<<g_rl.q[1]<<","<<g_rl.q[2]<<","<<g_rl.q[3]<<","<<g_rl.q[4]<<"\n";
  NS_LOG_INFO("Written: "<<Out("summary.csv"));
}

// ════════════════════════════════════════════════════════════
// MAIN
// ════════════════════════════════════════════════════════════
int main(int argc,char *argv[])
{
  CommandLine cmd(__FILE__);
  cmd.AddValue("simTime",     "Simulation time (s)",    g_simTime);
  cmd.AddValue("attackStart", "Attack start time (s)",  g_attackStart);
  cmd.AddValue("evalInterval","RL eval interval (s)",   g_evalInterval);
  cmd.AddValue("epsilon",     "Initial epsilon",        g_epsilon);
  cmd.AddValue("seed",        "Random seed",            g_seed);
  cmd.AddValue("outDir",      "Output directory",       g_outDir);
  cmd.Parse(argc,argv);

  Time::SetResolution(Time::NS);
  RngSeedManager::SetSeed(g_seed);
  LogComponentEnable("MqttAttack1Broker",LOG_LEVEL_INFO);

  MkDir(g_outDir); MkDir(g_outDir+"/pcap");

  // ── Nodes ──────────────────────────────────────────────────────────────
  NodeContainer brokers;   brokers.Create(1);   // Node 0
  NodeContainer sensors;   sensors.Create(6);   // Nodes 1-6
  NodeContainer attackers; attackers.Create(1); // Node 7

  NodeContainer allNodes;
  allNodes.Add(brokers); allNodes.Add(sensors); allNodes.Add(attackers);

  // ── Mobility ── star layout with attacker offset ───────────────────────
  MobilityHelper mob;
  mob.SetMobilityModel("ns3::ConstantPositionMobilityModel");
  {
    Ptr<ListPositionAllocator> p=CreateObject<ListPositionAllocator>();
    p->Add(Vector(50,50,0)); // Broker centre
    for(int i=0;i<6;i++){   // Sensors circle r=35
      double angle=i*(2.0*M_PI/6.0)-(M_PI/2.0);
      p->Add(Vector(50+35*cos(angle), 50+35*sin(angle), 0));
    }
    p->Add(Vector(50,95,0)); // Attacker bottom-centre
    mob.SetPositionAllocator(p);
    mob.Install(allNodes);
  }

  // ── WiFi ───────────────────────────────────────────────────────────────
  YansWifiChannelHelper ch=YansWifiChannelHelper::Default();
  YansWifiPhyHelper phy; phy.SetChannel(ch.Create());
  NetDeviceContainer devs=WNet(allNodes,"mqtt-attack",phy);
  phy.EnablePcap(g_outDir+"/pcap/broker",   devs.Get(0),true);
  phy.EnablePcap(g_outDir+"/pcap/attacker", devs.Get(7),true);

  // ── Internet stack ─────────────────────────────────────────────────────
  InternetStackHelper stack; stack.Install(allNodes);
  Ipv4AddressHelper ip4;
  ip4.SetBase("10.0.0.0","255.255.255.0");
  Ipv4InterfaceContainer ifc=ip4.Assign(devs);
  Ipv4GlobalRoutingHelper::PopulateRoutingTables();

  g_brokerIP  =ifc.GetAddress(0); // 10.0.0.1
  g_attackerIP=ifc.GetAddress(7); // 10.0.0.8
  NS_LOG_INFO("Broker="<<g_brokerIP<<"  Attacker="<<g_attackerIP);

  // ── Broker app ─────────────────────────────────────────────────────────
  {
    Ptr<MqttBrokerApp> a=CreateObject<MqttBrokerApp>();
    a->Setup(MQTT_PORT); brokers.Get(0)->AddApplication(a);
    a->SetStartTime(Seconds(0.5)); a->SetStopTime(Seconds(g_simTime));
  }

  // ── Sensor apps ─────────────────────────────────────────────────────────
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
    Ptr<MqttSensorApp> a=CreateObject<MqttSensorApp>();
    a->Setup(g_brokerIP,MQTT_PORT,
             std::string("Sensor_")+sNames[c.si],
             c.topic, c.interval, g_simTime);
    sensors.Get(c.si)->AddApplication(a);
    a->SetStartTime(Seconds(1.0+c.si*0.1));
    a->SetStopTime(Seconds(g_simTime));
  }

  // ── Attack app ─────────────────────────────────────────────────────────
  g_rl.mode=0;
  {
    Ptr<MqttAttackApp> app=CreateObject<MqttAttackApp>();
    app->Setup(g_brokerIP,MQTT_PORT,g_rl.mode,g_simTime);
    attackers.Get(0)->AddApplication(app);
    app->SetStartTime(Seconds(g_attackStart));
    app->SetStopTime(Seconds(g_simTime));
    g_rl.app=app;
  }

  // ── FlowMonitor ────────────────────────────────────────────────────────
  FlowMonitorHelper fmh;
  g_mon=fmh.InstallAll();
  g_cls=DynamicCast<Ipv4FlowClassifier>(fmh.GetClassifier());

  // ── Schedule RL + timeseries ───────────────────────────────────────────
  Simulator::Schedule(Seconds(g_attackStart+g_evalInterval),&RLEval);
  Simulator::Schedule(Seconds(1.0),&SnapTS);

  // ── NetAnim ────────────────────────────────────────────────────────────
  // Layout:
  //   Green broker at centre (50,50)
  //   Blue sensors in circle around broker, radius=35
  //   RED attacker at bottom (50,95) — clearly separated from sensors
  //   All nodes labelled: type, IP, sensor model
  //   Attack mode legend shown via broker description update

  std::string animFile=Out("mqtt-attack-anim.xml");
  AnimationInterface anim(animFile);

  // Broker
  anim.SetConstantPosition(brokers.Get(0), 50.0, 50.0);
  anim.UpdateNodeDescription(brokers.Get(0),
    "MQTT BROKER\n10.0.0.1 | Port:1883\n[TARGET of DDoS]");
  anim.UpdateNodeColor(brokers.Get(0), 34, 180, 100);
  anim.UpdateNodeSize(brokers.Get(0)->GetId(), 5.5, 5.5);

  // Sensors — circle
  struct SInfo{ const char *label; uint8_t r,g,b; };
  SInfo sinfo[]={
    {"S1: Temp & Humidity\n10.0.0.2 | DHT22\nInterval:2s",    70,130,255},
    {"S2: Water Level\n10.0.0.3 | HC-SR04\nInterval:3s",      70,130,255},
    {"S3: Ultrasonic\n10.0.0.4 | HC-SR04\nInterval:1s",       70,130,255},
    {"S4: Flame / IR\n10.0.0.5 | KY-026\nInterval:2s",        255,160, 30},
    {"S5: Motion (PIR)\n10.0.0.6 | HC-SR501\nInterval:1s",    70,130,255},
    {"S6: Light (LDR)\n10.0.0.7 | BH1750\nInterval:2s",       70,130,255},
  };
  for(int i=0;i<6;i++){
    double angle=i*(2.0*M_PI/6.0)-(M_PI/2.0);
    double x=50.0+35.0*cos(angle);
    double y=50.0+35.0*sin(angle);
    anim.SetConstantPosition(sensors.Get(i), x, y);
    anim.UpdateNodeDescription(sensors.Get(i), sinfo[i].label);
    anim.UpdateNodeColor(sensors.Get(i), sinfo[i].r, sinfo[i].g, sinfo[i].b);
    anim.UpdateNodeSize(sensors.Get(i)->GetId(), 3.5, 3.5);
  }

  // Attacker
  anim.SetConstantPosition(attackers.Get(0), 50.0, 95.0);
  anim.UpdateNodeDescription(attackers.Get(0),
    "! ATTACKER !\n10.0.0.8 | RL-DDoS Agent\n5 Attack Modes");
  anim.UpdateNodeColor(attackers.Get(0), 220, 40, 40);
  anim.UpdateNodeSize(attackers.Get(0)->GetId(), 4.5, 4.5);

  anim.EnablePacketMetadata(true);
  NS_LOG_INFO("NetAnim → "<<animFile);

  // ── Run ────────────────────────────────────────────────────────────────
  Simulator::Stop(Seconds(g_simTime+1.0));
  NS_LOG_INFO("=== Attack 1-Broker MQTT RL simulation starting ===");
  Simulator::Run();

  // ── Outputs ────────────────────────────────────────────────────────────
  g_mon->CheckForLostPackets();
  g_mon->SerializeToXmlFile(Out("mqtt-attack-flowmonitor.xml"),true,true);
  WriteFlowsCsv(); WriteRLCsv(); WriteTsCsv(); WriteSumCsv();

  std::cout<<"\n╔══════════════════════════════════════════════════════════╗\n";
  std::cout<<"║  MQTT 1-Broker RL-DDoS Simulation — Complete           ║\n";
  std::cout<<"╚══════════════════════════════════════════════════════════╝\n\n";
  std::cout<<"  Topology  : 1 Broker + 6 Sensors + 1 RL Attacker\n";
  std::cout<<"  Protocol  : MQTT 3.1.1 over TCP:1883\n";
  std::cout<<"  Attack    : starts at t="<<g_attackStart<<"s\n";
  std::cout<<"  Wireshark : open .pcap → filter: mqtt\n\n";
  std::cout<<"  RL FINAL Q-TABLE:\n";
  for(int m=0;m<N_MODES;m++)
    std::cout<<"    ["<<m<<"] "<<std::setw(8)<<ATK[m].shortName
             <<"  Q="<<std::fixed<<std::setprecision(3)<<g_rl.q[m]
             <<"  used="<<(int)g_rl.mU[m]<<"\n";
  std::cout<<"  steps="<<g_rl.steps<<"  eps="<<g_rl.eps<<"\n\n";

  Simulator::Destroy();
  NS_LOG_INFO("Done.");
  return 0;
}
