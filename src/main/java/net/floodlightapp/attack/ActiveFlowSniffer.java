package net.floodlightapp.attack;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import javax.sound.midi.MidiDevice.Info;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.util.MACAddress;

import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.OFStatisticsReply;
import org.openflow.protocol.OFStatisticsRequest;
import org.openflow.protocol.OFType;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.protocol.statistics.OFFlowStatisticsReply;
import org.openflow.protocol.statistics.OFFlowStatisticsRequest;
import org.openflow.protocol.statistics.OFStatistics;
import org.openflow.protocol.statistics.OFStatisticsType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
/**
 * 
 * @author shichao
 *
 */
public class ActiveFlowSniffer extends FlowAssembler {

	private enum STATE {
		POLLING, POLLING_WAIT, PACK_IN_WAIT, FINISHED, TERMINATED
	};

	private final int NUM = 1; // number of active flows to report before
								// stopping
	private final int DELTA_THRESH = 5;

	public static Logger log = LoggerFactory.getLogger(ActiveFlowSniffer.class);

	private STATE state;
	private int reportNum; // number of active flows found
	private int xid;
	private HashSet<IOFSwitch> sw_heard;
	private List<SwitchFlowStatTuple> flow_heard;
	private Map<MACTuple, List<FlowStatChain>> map;

	private Thread sniffThread;

	@Override
	public String getName() {
		return "Flow Sniffer";
	}

	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		//log.info("Message received");
		if (msg.getType() == OFType.STATS_REPLY
				&& this.state == STATE.POLLING_WAIT) {
			List<SwitchFlowStatTuple> tuples = recvSniff(sw, msg);
			sw_heard.add(sw);
			flow_heard.addAll(tuples);

			if (sw_heard.size() == floodlightProvider.getSwitches().size()) {
				// All switch heard from
				log.info("All switch msg heard");
				FlowStatChain flowChain = this.assemble(flow_heard);
				
				if (flowChain != null) {
					log.info("Find a flow chain");
					MACTuple tuple = flowChain.getMACTuple();
					if (!map.containsKey(tuple)) {
						map.put(tuple, new ArrayList<FlowStatChain>());
					}
					map.get(tuple).add(flowChain);
					
				} else{
					//log.info("No flow chain found");
				}
				
				sw_heard.clear();
				flow_heard.clear();
				this.state = STATE.POLLING;
				
				//log.info("Wake up the thread");
				
				synchronized (this) {
					this.notify();
				}

			} else {
				this.state = STATE.POLLING_WAIT;
			}

		}
		return null;
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		super.init(context);
		this.state = STATE.FINISHED;
		this.sw_heard = new HashSet<IOFSwitch>();
		this.flow_heard = new ArrayList<SwitchFlowStatTuple>();
		this.reportNum = 0;
		this.xid = 1111;
		this.map = new HashMap<MACTuple, List<FlowStatChain>>();
	}

	@Override
	public void startUp(FloodlightModuleContext context) {
		super.startUp(context);
		floodlightProvider.addOFMessageListener(OFType.STATS_REPLY, this);
		sniffThread = new Thread(new ActiveFlowSnifferRunnable());
		sniffThread.setName("Sniff Thread");
		sniffThread.start();
	}

	private void loop() {
		// while loop, exit if it is waiting for the message from controller
		while (this.state != STATE.TERMINATED) {
			//log.info("State {}", this.state);
			switch (this.state) {
			case FINISHED:
				if (reportNum < NUM) {
					this.state = STATE.POLLING;
				} else {
					this.state = STATE.TERMINATED;
				}
				break;
			case POLLING:
				MACTuple readyTuple;
				if ((readyTuple = decesionMade()) != null) {
					log.info("Active flow found: " + readyTuple.getSrc()
							+ " -> " + readyTuple.getDst());
					this.state = STATE.TERMINATED;
				} else {
					// before sending sniff, have a snap
					try {
						Thread.sleep(5000);
					} catch (InterruptedException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}

					if (sendSniff()) {
						this.state = STATE.POLLING_WAIT;
						//log.info("Sniff Sent");
					} else {
						this.state = STATE.POLLING;
						//log.info("Sniff Failed");
					}
				}
				break;
			case POLLING_WAIT:
				synchronized (this) {
					try {
						this.wait();
					} catch (InterruptedException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
				//log.info("Jump from busy wait");
				//log.info("Now the map has {} tuples", map.size());
				for(MACTuple t:map.keySet()){
					for(FlowStatChain chain: map.get(t)){
						String info = "";
						info += t + " : ";
						for(SwitchFlowStatTuple tt : chain.getSwitchFlowStatList()){
							long swid = tt.getSwitch().getId();
							short outport = ((OFActionOutput) tt.getFlowStat().getActions().get(0)).getPort();
							short inport = tt.getFlowStat().getMatch().getInputPort();
							info += swid + "(" + inport + ")->" + swid + "(" + outport + ")->";
						}
						info = info.substring(0, info.length() - 2);
						info += " Matched Packet : " + chain.getMatchCount();
						log.info(info);
					}
				}
				break;
			case TERMINATED:
				break;
			}
		}
	}

	private MACTuple decesionMade() {
		for (MACTuple t : map.keySet()) {
			int delta_num = 0;
			for (int i = 1; i < map.get(t).size(); i++) {
				if (map.get(t).get(i).getMatchCount() > map.get(t).get(i)
						.getMatchCount()) {
					delta_num++;
				}
			}
			if (delta_num > DELTA_THRESH) {
				// report that as active
				return t;
			}
		}
		return null;
	}

	private boolean sendSniff() {
		if (floodlightProvider.getSwitches().size() == 0) {
			log.error("Sorry I know none of the switches");
			return false;
		}
		for (long key : floodlightProvider.getSwitches().keySet()) {
			IOFSwitch sw = floodlightProvider.getSwitches().get(key);
			if (sw == null) {
				log.error("Too fast");
				return false;
			}
			sendSniffSwitch(sw);
		}
		return true;
	}

	private void sendSniffSwitch(IOFSwitch sw) {
		OFStatisticsRequest req = (OFStatisticsRequest) floodlightProvider
				.getOFMessageFactory().getMessage(OFType.STATS_REQUEST);
		req.setStatisticType(OFStatisticsType.FLOW);
		OFFlowStatisticsRequest specificReq = new OFFlowStatisticsRequest();
		OFMatch match = new OFMatch();
		match.setWildcards(0xffffffff);
		specificReq.setMatch(match);
		specificReq.setOutPort(OFPort.OFPP_NONE.getValue());
		specificReq.setTableId((byte) 0xff);
		req.setStatistics(Collections.singletonList((OFStatistics) specificReq));
		req.setLengthU(req.getLengthU() + specificReq.getLength());
		try {
			sw.sendStatsQuery(req, xid++, this);
			sw.flush();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private List<SwitchFlowStatTuple> recvSniff(IOFSwitch sw, OFMessage msg) {
		List<SwitchFlowStatTuple> list = new ArrayList<SwitchFlowStatTuple>();

		if (msg.getType() == OFType.STATS_REPLY) {
			OFStatisticsReply sr = (OFStatisticsReply) msg;
			for (OFStatistics stat : sr.getStatistics()) {
				if (stat instanceof OFFlowStatisticsReply) {
					OFFlowStatisticsReply flowStat = (OFFlowStatisticsReply) stat;
					SwitchFlowStatTuple tuple = new SwitchFlowStatTuple();
					tuple.setSwitch(sw);
					tuple.setFlowStat(flowStat);
					list.add(tuple);

				}
			}
		}
		return list;
	}

	private class ActiveFlowSnifferRunnable implements Runnable {

		@Override
		public void run() {
			try {
				Thread.sleep(20000);
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			loop();
		}

	}

}
