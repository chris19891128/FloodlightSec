package net.floodlightapp.attack;

import java.util.ArrayList;
import java.util.List;

import net.floodlightcontroller.util.MACAddress;

import org.openflow.protocol.statistics.OFFlowStatisticsReply;
/**
 * 
 * @author shichao
 *
 */
public class FlowStatChain {

	private List<SwitchFlowStatTuple> tuples;
	private long count;

	public FlowStatChain() {
		count = -1;
	}

	public List<SwitchFlowStatTuple> getSwitchFlowStatList() {
		return tuples;
	}

	public void setSwitchFlowStatList(List<SwitchFlowStatTuple> tuples) {
		this.tuples = tuples;
	}

	// functions for demo only, cannot guarantee that the flow chain is not dl
	// addr wildcarded
	public MACTuple getMACTuple() {
		byte[] src = tuples.get(0).getFlowStat().getMatch()
				.getDataLayerSource();
		byte[] dst = tuples.get(0).getFlowStat().getMatch()
				.getDataLayerDestination();
		return new MACTuple(new MACAddress(src), new MACAddress(dst));
	}

	public long getMatchCount() {
		if (this.count < 0) {
			long min = Long.MAX_VALUE;
			for (SwitchFlowStatTuple t : tuples) {
				if (t.getFlowStat().getPacketCount() < min) {
					min = t.getFlowStat().getPacketCount();
				}
			}
			if (min < Long.MAX_VALUE) {
				this.count = min;
			} else {
				this.count = -1;
			}
		}
		return this.count;

	}

}
