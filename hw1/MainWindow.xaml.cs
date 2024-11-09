using PacketDotNet;
using SharpPcap;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace hw1
{
  public partial class MainWindow : Window
  {
    private ICaptureDevice device;
    private ObservableCollection<PacketInfo> Packets { get; set; }
    private int packetNo;

    public ICollectionView PacketsView { get; set; }

    public MainWindow()
    {
      InitializeComponent();

      DataContext = this;
      Packets = new ObservableCollection<PacketInfo>();
      packetNo = 1;
      PacketsView = CollectionViewSource.GetDefaultView(Packets);

      PacketContent.Items.Clear();

      foreach (var dev in CaptureDeviceList.Instance)
      {
        DeviceComboBox.Items.Add(dev.Description);
      }
      if (DeviceComboBox.Items.Count == 0)
      {
        throw new Exception("没有设备！");
      }
      device = CaptureDeviceList.Instance[0];
      DeviceComboBox.SelectedIndex = 0;

      FilterComboBox.ItemsSource = new[] { "所有", "HTTP", "TCP", "UDP", "IPv4", "ICMPv4", "IPv6", "ICMPv6", "以太网" };
      FilterComboBox.SelectedIndex = 0;
    }

    private void DeviceComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
      device.StopCapture();
      device.Close();
      Packets.Clear();
      packetNo = 1;

      device = CaptureDeviceList.Instance[DeviceComboBox.SelectedIndex];
      device.OnPacketArrival += Device_OnPacketArrival;
    }

    private void StartButton_Click(object sender, RoutedEventArgs e)
    {
      device.OnPacketArrival += Device_OnPacketArrival;
      device.Open(DeviceModes.Promiscuous);
      device.StartCapture();
    }

    private void EndButton_Click(object sender, RoutedEventArgs e)
    {
      device.StopCapture();
      device.Close();
    }

    private void Device_OnPacketArrival(object sender, PacketCapture e)
    {
      PacketInfo packetInfo = new PacketInfo
      {
        Time = TimeZoneInfo.ConvertTime(DateTimeOffset.FromUnixTimeSeconds((long)e.GetPacket().Timeval.Value), TimeZoneInfo.Local).ToString(),
        Length = e.GetPacket().PacketLength,
        Data = e.GetPacket().Data,
      };

      try
      {
        Packet packet = Packet.ParsePacket(e.GetPacket().LinkLayerType, e.GetPacket().Data);

        if (packet is EthernetPacket ethernetPacket)
        {
          packetInfo.LinkProtocol = "以太网";
          packetInfo.SrcPhysAddr = ethernetPacket.SourceHardwareAddress.ToString();
          packetInfo.DstPhysAddr = ethernetPacket.DestinationHardwareAddress.ToString();

          if (ethernetPacket.PayloadPacket is IPPacket ipPacket)
          {
            packetInfo.SrcIP = ipPacket.SourceAddress.ToString();
            packetInfo.DstIP = ipPacket.DestinationAddress.ToString();
            if (ipPacket is IPv4Packet)
            {
              packetInfo.InternetProtocol = "IPv4";
            }
            else if (ipPacket is IPv6Packet)
            {
              packetInfo.InternetProtocol = "IPv6";
            }

            if (ipPacket.PayloadPacket is TcpPacket tcpPacket)
            {
              packetInfo.TransportProtocol = "TCP";
              packetInfo.SrcPort = tcpPacket.SourcePort;
              packetInfo.DstPort = tcpPacket.DestinationPort;
            }
            else if (ipPacket.PayloadPacket is UdpPacket udpPacket)
            {
              packetInfo.TransportProtocol = "UDP";
              packetInfo.SrcPort = udpPacket.SourcePort;
              packetInfo.DstPort = udpPacket.DestinationPort;
            }
            else if (ipPacket.PayloadPacket is IcmpV4Packet)
            {
              packetInfo.InternetProtocol = "ICMPv4";
            }
            else if (ipPacket.PayloadPacket is IcmpV6Packet)
            {
              packetInfo.InternetProtocol = "ICMPv6";
            }

            if (packetInfo.SrcPort == 80 || packetInfo.DstPort == 80)
            {
              packetInfo.ApplicationProtocol = "HTTP";
            }
          }
        }

        if (packetInfo.ApplicationProtocol != null)
        {
          packetInfo.Protocol = packetInfo.ApplicationProtocol;
          packetInfo.Source = packetInfo.SrcIP + ":" + packetInfo.SrcPort;
          packetInfo.Destination = packetInfo.DstIP + ":" + packetInfo.DstPort;
        }
        else if (packetInfo.TransportProtocol != null)
        {
          packetInfo.Protocol = packetInfo.TransportProtocol;
          packetInfo.Source = packetInfo.SrcIP + ":" + packetInfo.SrcPort;
          packetInfo.Destination = packetInfo.DstIP + ":" + packetInfo.DstPort;
        }
        else if (packetInfo.InternetProtocol != null)
        {
          packetInfo.Protocol = packetInfo.InternetProtocol;
          packetInfo.Source = packetInfo.SrcIP;
          packetInfo.Destination = packetInfo.DstIP;
        }
        else if (packetInfo.LinkProtocol != null)
        {
          packetInfo.Protocol = packetInfo.LinkProtocol;
          packetInfo.Source = packetInfo.SrcPhysAddr;
          packetInfo.Destination = packetInfo.DstPhysAddr;
        }
        else
        {
          packetInfo.Protocol = "未知";
        }
      }
      catch { packetInfo.Protocol = "未知"; }

      Dispatcher.Invoke(() =>
      {
        packetInfo.No = packetNo++;
        Packets.Add(packetInfo);
      });
    }

    private void FilterComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
      string filter = FilterComboBox.SelectedItem.ToString();

      switch (filter)
      {
        case "所有":
          PacketsView.Filter = null;
          break;

        case "TCP":
        case "UDP":
          PacketsView.Filter = obj =>
          {
            return obj is PacketInfo packet && packet.TransportProtocol == filter;
          };
          break;

        case "IPv4":
        case "ICMPv4":
        case "IPv6":
        case "ICMPv6":
          PacketsView.Filter = obj =>
          {
            return obj is PacketInfo packet && packet.InternetProtocol == filter;
          };
          break;

        case "以太网":
          PacketsView.Filter = obj =>
          {
            return obj is PacketInfo packet && packet.LinkProtocol == filter;
          };
          break;

        default:
          PacketsView.Filter = obj =>
          {
            return obj is PacketInfo packet && packet.Protocol == filter;
          };
          break;
      }
    }

    private void PacketList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
      PacketDetail.Text = "";
      if (PacketList.SelectedItem is PacketInfo packet)
      {
        if (packet.LinkProtocol != null)
        {
          PacketDetail.Text += string.Format("链路层协议：{0}，源物理地址：{1}，目的物理地址：{2}\n", packet.LinkProtocol, packet.SrcPhysAddr, packet.DstPhysAddr);
        }
        if (packet.InternetProtocol != null)
        {
          PacketDetail.Text += string.Format("网络层协议：{0}，源IP地址：{1}，目的IP地址：{2}\n", packet.InternetProtocol, packet.SrcIP, packet.DstIP);
        }
        if (packet.TransportProtocol != null)
        {
          PacketDetail.Text += string.Format("传输层协议：{0}，源端口：{1}，目的端口：{2}\n", packet.TransportProtocol, packet.SrcPort, packet.DstPort);
        }
        if (packet.ApplicationProtocol != null)
        {
          PacketDetail.Text += string.Format("应用层协议：{0}\n", packet.ApplicationProtocol);
        }

        var hexData = new List<HexLine>();
        int totalRow = (packet.Length + 1) / 8;
        for (int row = 0; row < totalRow; row++)
        {
          StringBuilder sb = new StringBuilder();
          for (int col = 0; col < 16; col++)
          {
            int i = row * 8 + col;
            if (i < packet.Length)
            {
              sb.AppendFormat("{0:X2} ", packet.Data[i]);
              if (col == 7)
              {
                sb.Append(" ");
              }
            }
          }
          hexData.Add(new HexLine { No = row, Content = sb.ToString() });
        }

        PacketContent.ItemsSource = hexData;
      }
    }
  }

  public class PacketInfo
  {
    public int No { get; set; }
    public string Time { get; set; }
    public string Source { get; set; }
    public string Destination { get; set; }
    public string Protocol { get; set; }
    public int Length { get; set; }
    public byte[] Data { get; set; }
    public string LinkProtocol { get; set; }
    public string SrcPhysAddr { get; set; }
    public string DstPhysAddr { get; set; }
    public string InternetProtocol { get; set; }
    public string SrcIP { get; set; }
    public string DstIP { get; set; }
    public string TransportProtocol { get; set; }
    public int SrcPort { get; set; }
    public int DstPort { get; set; }
    public string ApplicationProtocol { get; set; }
  }

  public class HexLine
  {
    public int No { get; set; }
    public string Content { get; set; }
    public string HexNo => $"{No:X}";
  }
}
