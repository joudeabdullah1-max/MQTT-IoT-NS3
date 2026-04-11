/* =============================================================================
 * NS-3 MQTT IoT Simulation — 1 Broker, 6 Sensors, NO ATTACKS
 * =============================================================================
 *
 * TOPOLOGY
 *   Wireless 802.11b Ad-Hoc, subnet 10.0.0.0/24
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
 *
 * MQTT TOPICS & PAYLOADS
 *   sensors/temperature_humidity  → "T:24.5 H:61.3"
 *   sensors/water_level           → "Level:Normal" / "Level:High"
 *   sensors/ultrasonic            → "18.938 cm"
 *   sensors/flame_ir              → "0" (safe) / "Flame Detected!"
 *   sensors/motion                → "Motion Detected!" / "No Motion"
 *   sensors/light                 → "Lux:320.5"
 *
 * OUTPUT → normal_1broker_output/
 *   pcap/  flows.csv  timeseries.csv  summary.csv
 *   mqtt-normal-anim.xml  mqtt-normal-flowmonitor.xml
 *
 * BUILD:
 *   cp mqtt_1broker_normal.cc $NS3_DIR/scratch/
 *   cd $NS3_DIR && ./ns3 run scratch/mqtt_1broker_normal
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
NS_LOG_COMPONENT_DEFINE ("MqttNormal1Broker");

// ════════════════════════════════════════════════════════════
// PARAMETERS
// ════════════════════════════════════════════════════════════
static const uint16_t MQTT_PORT = 1883;
static double      g_simTime   = 60.0;
static std::string g_outDir    = "normal_1broker_output";

// ════════════════════════════════════════════════════════════
// MQTT FRAME BUILDER — MQTT 3.1.1 binary frames
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

std::vector<uint8_t> Connect(const std::string &cid){
  std::vector<uint8_t> vh;
  app(vh,mstr("MQTT")); vh.push_back(0x04); vh.push_back(0x02);
  vh.push_back(0x00); vh.push_back(0x3C);
  std::vector<uint8_t> pay; app(pay,mstr(cid));
  std::vector<uint8_t> rem; app(rem,vh); app(rem,pay);
  std::vector<uint8_t> f; f.push_back(0x10);
  app(f,varlen(rem.size())); app(f,rem); return f;
}

std::vector<uint8_t> ConnAck(uint8_t rc=0x00){
  return {0x20,0x02,0x00,rc};
}

std::vector<uint8_t> Publish(const std::string &topic, const std::string &payload){
  std::vector<uint8_t> rem; app(rem,mstr(topic));
  for(char c:payload) rem.push_back((uint8_t)c);
  std::vector<uint8_t> f; f.push_back(0x30);
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
    static TypeId t=TypeId("MqttBrokerApp1N").SetParent<Application>()
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
    static TypeId t=TypeId("MqttSensorApp1N").SetParent<Application>()
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
// HELPERS
// ════════════════════════════════════════════════════════════
void MkDir(const std::string &p){ mkdir(p.c_str(),0755); }
std::string Out(const std::string &f){ return g_outDir+"/"+f; }

static Ptr<FlowMonitor>        g_mon;
static Ptr<Ipv4FlowClassifier> g_cls;

struct TsEntry{double t;uint64_t sB;};
static std::vector<TsEntry> g_ts;
static uint64_t g_pS=0;

void SnapTS(){
  g_mon->CheckForLostPackets();
  uint64_t sB=0;
  for(auto &f:g_mon->GetFlowStats()) sB+=f.second.txBytes;
  g_ts.push_back({Simulator::Now().GetSeconds(),sB-g_pS});
  g_pS=sB;
  if(Simulator::Now().GetSeconds()<g_simTime-0.5)
    Simulator::Schedule(Seconds(1.0),&SnapTS);
}

NetDeviceContainer WNet(NodeContainer n, const std::string &ssid, YansWifiPhyHelper &phy){
  WifiHelper w; w.SetStandard(WIFI_STANDARD_80211b);
  w.SetRemoteStationManager("ns3::ConstantRateWifiManager",
    "DataMode",StringValue("DsssRate11Mbps"),
    "ControlMode",StringValue("DsssRate11Mbps"));
  WifiMacHelper mac; mac.SetType("ns3::AdhocWifiMac");
  return w.Install(phy,mac,n);
}

void WriteFlowsCsv(){
  std::ofstream f(Out("flows.csv"));
  f<<"flow_id,src_ip,src_port,dst_ip,dst_port,tx_packets,rx_packets,"
   <<"lost_packets,loss_pct,avg_delay_ms,throughput_mbps\n";
  for(auto &fl:g_mon->GetFlowStats()){
    auto t=g_cls->FindFlow(fl.first);
    double lp=fl.second.txPackets>0?100.0*fl.second.lostPackets/fl.second.txPackets:0;
    double ad=fl.second.rxPackets>0?fl.second.delaySum.GetSeconds()/fl.second.rxPackets*1000:0;
    double tp=0;
    if(fl.second.timeLastRxPacket>fl.second.timeFirstTxPacket){
      double d=(fl.second.timeLastRxPacket-fl.second.timeFirstTxPacket).GetSeconds();
      tp=fl.second.rxBytes*8.0/d/1e6;
    }
    f<<fl.first<<","<<t.sourceAddress<<","<<t.sourcePort<<","
     <<t.destinationAddress<<","<<t.destinationPort<<","
     <<fl.second.txPackets<<","<<fl.second.rxPackets<<","
     <<fl.second.lostPackets<<","
     <<std::fixed<<std::setprecision(2)<<lp<<","
     <<std::setprecision(3)<<ad<<","<<std::setprecision(6)<<tp<<"\n";
  }
  NS_LOG_INFO("Written: "<<Out("flows.csv"));
}

void WriteTsCsv(){
  std::ofstream f(Out("timeseries.csv"));
  f<<"time_s,sensor_bytes,sensor_kbps\n";
  for(auto &e:g_ts)
    f<<std::fixed<<std::setprecision(1)<<e.t<<","<<e.sB<<","
     <<std::setprecision(2)<<e.sB*8.0/1000<<"\n";
  NS_LOG_INFO("Written: "<<Out("timeseries.csv"));
}

void WriteSumCsv(uint64_t sTx,uint64_t sRx,uint64_t sL,uint64_t sTB){
  std::ofstream f(Out("summary.csv"));
  f<<"category,tx_packets,rx_packets,lost_packets,loss_pct,tx_bytes\n";
  double lp=sTx>0?100.0*sL/sTx:0;
  f<<"sensor,"<<sTx<<","<<sRx<<","<<sL<<","
   <<std::fixed<<std::setprecision(2)<<lp<<","<<sTB<<"\n";
  NS_LOG_INFO("Written: "<<Out("summary.csv"));
}

// ════════════════════════════════════════════════════════════
// MAIN
// ════════════════════════════════════════════════════════════
int main(int argc,char *argv[])
{
  CommandLine cmd(__FILE__);
  cmd.AddValue("simTime","Simulation time (s)",g_simTime);
  cmd.AddValue("outDir", "Output directory",  g_outDir);
  cmd.Parse(argc,argv);

  Time::SetResolution(Time::NS);
  RngSeedManager::SetSeed(42);
  LogComponentEnable("MqttNormal1Broker",LOG_LEVEL_INFO);

  MkDir(g_outDir); MkDir(g_outDir+"/pcap");

  // ── Nodes ──────────────────────────────────────────────────────────────
  NodeContainer brokers; brokers.Create(1);  // Node 0 = Broker
  NodeContainer sensors; sensors.Create(6);  // Nodes 1-6 = Sensors

  NodeContainer allNodes;
  allNodes.Add(brokers); allNodes.Add(sensors);

  // ── Mobility — star layout: broker centre, sensors in circle ──────────
  MobilityHelper mob;
  mob.SetMobilityModel("ns3::ConstantPositionMobilityModel");
  {
    Ptr<ListPositionAllocator> p=CreateObject<ListPositionAllocator>();
    p->Add(Vector(50,50,0)); // Broker at centre
    // 6 sensors evenly spaced in circle, radius=35
    for(int i=0;i<6;i++){
      double angle=i*(2.0*M_PI/6.0)-(M_PI/2.0);
      p->Add(Vector(50+35*cos(angle), 50+35*sin(angle), 0));
    }
    mob.SetPositionAllocator(p);
    mob.Install(allNodes);
  }

  // ── WiFi ───────────────────────────────────────────────────────────────
  YansWifiChannelHelper ch=YansWifiChannelHelper::Default();
  YansWifiPhyHelper phy; phy.SetChannel(ch.Create());
  NetDeviceContainer devs=WNet(allNodes,"mqtt-iot",phy);

  // PCAP capture
  phy.EnablePcap(g_outDir+"/pcap/broker", devs.Get(0),true);

  // ── Internet stack ─────────────────────────────────────────────────────
  InternetStackHelper stack;
  stack.Install(allNodes);
  Ipv4AddressHelper ip4;
  ip4.SetBase("10.0.0.0","255.255.255.0");
  Ipv4InterfaceContainer ifc=ip4.Assign(devs);
  Ipv4GlobalRoutingHelper::PopulateRoutingTables();

  Ipv4Address brokerIP=ifc.GetAddress(0); // 10.0.0.1
  NS_LOG_INFO("Broker IP = "<<brokerIP);

  // ── Broker app ─────────────────────────────────────────────────────────
  {
    Ptr<MqttBrokerApp> a=CreateObject<MqttBrokerApp>();
    a->Setup(MQTT_PORT);
    brokers.Get(0)->AddApplication(a);
    a->SetStartTime(Seconds(0.5));
    a->SetStopTime(Seconds(g_simTime));
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
    a->Setup(brokerIP,MQTT_PORT,
             std::string("Sensor_")+sNames[c.si],
             c.topic, c.interval, g_simTime);
    sensors.Get(c.si)->AddApplication(a);
    a->SetStartTime(Seconds(1.0+c.si*0.1));
    a->SetStopTime(Seconds(g_simTime));
  }

  // ── FlowMonitor ────────────────────────────────────────────────────────
  FlowMonitorHelper fmh;
  g_mon=fmh.InstallAll();
  g_cls=DynamicCast<Ipv4FlowClassifier>(fmh.GetClassifier());
  Simulator::Schedule(Seconds(1.0),&SnapTS);

  // ── NetAnim ────────────────────────────────────────────────────────────
  // Clean star topology: Broker at centre (50,50)
  // Sensors arranged in a circle, each labelled with sensor type and IP
  std::string animFile=Out("mqtt-normal-anim.xml");
  AnimationInterface anim(animFile);

  // Broker — large green node at centre
  anim.SetConstantPosition(brokers.Get(0), 50.0, 50.0);
  anim.UpdateNodeDescription(brokers.Get(0),
    "MQTT BROKER\n10.0.0.1\nPort:1883");
  anim.UpdateNodeColor(brokers.Get(0), 34, 180, 100);   // green
  anim.UpdateNodeSize(brokers.Get(0)->GetId(), 5.0, 5.0);

  // Sensor label info
  struct SInfo{ const char *label; uint8_t r,g,b; };
  SInfo sinfo[]={
    {"S1: Temp & Humidity\n10.0.0.2\nDHT22",          70,130,255},
    {"S2: Water Level\n10.0.0.3\nHC-SR04",            70,130,255},
    {"S3: Ultrasonic\n10.0.0.4\nHC-SR04",             70,130,255},
    {"S4: Flame / IR\n10.0.0.5\nKY-026",              255,160, 30},
    {"S5: Motion (PIR)\n10.0.0.6\nHC-SR501",          70,130,255},
    {"S6: Light (LDR)\n10.0.0.7\nBH1750",             70,130,255},
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
  anim.EnablePacketMetadata(true);
  NS_LOG_INFO("NetAnim → "<<animFile);

  // ── Run ────────────────────────────────────────────────────────────────
  Simulator::Stop(Seconds(g_simTime+1.0));
  NS_LOG_INFO("=== Normal 1-Broker MQTT simulation starting ===");
  Simulator::Run();

  // ── Outputs ────────────────────────────────────────────────────────────
  g_mon->CheckForLostPackets();
  g_mon->SerializeToXmlFile(Out("mqtt-normal-flowmonitor.xml"),true,true);
  WriteFlowsCsv(); WriteTsCsv();

  uint64_t sTx=0,sRx=0,sL=0,sTB=0;
  for(auto &fl:g_mon->GetFlowStats()){
    sTx+=fl.second.txPackets; sRx+=fl.second.rxPackets;
    sL+=fl.second.lostPackets; sTB+=fl.second.txBytes;
  }
  WriteSumCsv(sTx,sRx,sL,sTB);

  std::cout<<"\n╔══════════════════════════════════════════════════════════╗\n";
  std::cout<<"║  MQTT 1-Broker Normal Simulation — Complete             ║\n";
  std::cout<<"╚══════════════════════════════════════════════════════════╝\n\n";
  std::cout<<"  Topology  : 1 Broker + 6 Sensors (Star, 802.11b)\n";
  std::cout<<"  Protocol  : MQTT 3.1.1 over TCP:1883\n";
  std::cout<<"  Duration  : "<<g_simTime<<" seconds\n";
  std::cout<<"  Wireshark : open .pcap → filter: mqtt\n\n";
  std::cout<<"  Output files in: "<<g_outDir<<"/\n";
  std::cout<<"  ├── pcap/broker-0-0.pcap\n";
  std::cout<<"  ├── flows.csv\n";
  std::cout<<"  ├── timeseries.csv\n";
  std::cout<<"  ├── summary.csv\n";
  std::cout<<"  ├── mqtt-normal-anim.xml\n";
  std::cout<<"  └── mqtt-normal-flowmonitor.xml\n\n";
  std::cout<<"  Sensor Topics:\n";
  std::cout<<"    sensors/temperature_humidity  (T:xx.x H:xx.x)\n";
  std::cout<<"    sensors/water_level           (Level:Normal|High)\n";
  std::cout<<"    sensors/ultrasonic            (xx.xxx cm)\n";
  std::cout<<"    sensors/flame_ir              (0 | Flame Detected!)\n";
  std::cout<<"    sensors/motion                (Motion Detected! | No Motion)\n";
  std::cout<<"    sensors/light                 (Lux:xxx.x)\n\n";

  Simulator::Destroy();
  NS_LOG_INFO("Done.");
  return 0;
}
