package net.floodlightapp.attack;

import java.util.List;

import net.floodlightcontroller.core.IOFSwitch;

import org.openflow.protocol.statistics.OFFlowStatisticsReply;
/**
 * 
 * @author shichao
 *
 */
public class SwitchFlowStatTuple {
	private IOFSwitch sw;
	private OFFlowStatisticsReply stats;

	public IOFSwitch getSwitch() {
		return sw;
	}

	public void setSwitch(IOFSwitch sw) {
		this.sw = sw;
	}

	public OFFlowStatisticsReply getFlowStat() {
		return stats;
	}

	public void setFlowStat(OFFlowStatisticsReply stats) {
		this.stats = stats;
	}

	

}
