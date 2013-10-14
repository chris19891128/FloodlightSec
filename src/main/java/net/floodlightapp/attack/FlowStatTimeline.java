package net.floodlightapp.attack;
/**
 * 
 * @author shichao
 *
 */
public class FlowStatTimeline {
	private int time;
	private FlowStatChain chain;
	private int count;
	
	public int getTime() {
		return time;
	}
	public void setTime(int time) {
		this.time = time;
	}
	public FlowStatChain getFlowStatChain() {
		return chain;
	}
	public void setFlowStatChain(FlowStatChain chain) {
		this.chain = chain;
	}
	public int getMatchCount() {
		return count;
	}
	public void setMatchCount(int count) {
		this.count = count;
	}
	
	
}
