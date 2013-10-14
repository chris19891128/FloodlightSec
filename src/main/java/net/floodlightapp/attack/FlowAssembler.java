package net.floodlightapp.attack;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.routing.Route;

import org.openflow.protocol.OFMatch;
import org.openflow.protocol.action.OFActionOutput;
/**
 * 
 * @author shichao
 *
 */
public abstract class FlowAssembler extends PlayBase {

	private static final int MAX_NODE = 100;

	private List<SwitchFlowStatTuple> list;
	private boolean[][] conn;

	@Override
	public String getName() {
		return "Flow Assembler";
	}

	public FlowStatChain assemble(List<SwitchFlowStatTuple> inlist) {
		// discover the first flow chain for demo
		list = new ArrayList<SwitchFlowStatTuple>();
		list.addAll(inlist);
		int size = inlist.size();
		conn = new boolean[size][];
		for (int i = 0; i < size; i++) {
			conn[i] = new boolean[size];
		}

		for (int i = 0; i < size; i++) {
			for (int j = 0; j < size; j++) {
				SwitchFlowStatTuple srct = list.get(i);
				SwitchFlowStatTuple dstt = list.get(j);
				if (srct.getSwitch().equals(dstt.getSwitch())) {
				} else if (!FlowAssembler.compareMatch(srct.getFlowStat()
						.getMatch(), dstt.getFlowStat().getMatch())) {
				} else {
					// suppose only forwarding action
					short outport = ((OFActionOutput) (srct.getFlowStat()
							.getActions().get(0))).getPort();
					short inport = dstt.getFlowStat().getMatch().getInputPort();
					IOFSwitch srcsw = srct.getSwitch();
					IOFSwitch dstsw = dstt.getSwitch();
					Route route = this.routingEngine.getRoute(srcsw.getId(),
							outport, dstsw.getId(), inport);
					if (route.getPath().size() == 4
							&& route.getPath().get(0)
									.equals(route.getPath().get(1))
							&& route.getPath().get(2)
									.equals(route.getPath().get(3))
							&& !route.getPath().get(1)
									.equals(route.getPath().get(2))) {
						// This is ugly. Hate the way route.getPath returns,
						// always passing each switch twice
						conn[i][j] = true;
					} else {
						conn[i][j] = false;
					}
				}
			}
		}

		int seed_src = -1, seed_dst = -1;
		ArrayList<SwitchFlowStatTuple> flow_path = new ArrayList<SwitchFlowStatTuple>();
		boolean found = false;
		for (int i = 0; i < size; i++) {
			for (int j = 0; j < size; j++) {
				if (conn[i][j]) {
					flow_path.add(list.get(i));
					flow_path.add(list.get(j));
					seed_src = i;
					seed_dst = j;
					found = true;
					break;
					
				}
			}
			if(found)
				break;
		}

		if (seed_src >= 0 && seed_dst >= 0) {
			int start = seed_src;
			while (true) {
				boolean flag = false;
				for (int i = 0; i < size; i++) {
					if (conn[i][start]) {
						start = i;
						flag = true;
						flow_path.add(0, list.get(i));
						break;
					}
				}
				if (!flag) {
					break;
				}
			}

			start = seed_dst;
			while (true) {
				boolean flag = false;
				for (int i = 0; i < size; i++) {
					if (conn[start][i]) {
						start = i;
						flag = true;
						flow_path.add(list.get(i));
						break;
					}
				}
				if (!flag) {
					break;
				}
			}
			FlowStatChain chain = new FlowStatChain();
			chain.setSwitchFlowStatList(flow_path);
			return chain;
		} else {
			System.err.println("Flow chain is null reason below");
			return null;
		}
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		super.init(context);
	}

	@Override
	public void startUp(FloodlightModuleContext context) {
		super.startUp(context);
	}

	public static boolean compareMatch(OFMatch one, OFMatch other) {
		if (one == other) {
			return true;
		}
		if (!Arrays.equals(one.getDataLayerDestination(),
				other.getDataLayerDestination())) {
			return false;
		}
		if (!Arrays
				.equals(one.getDataLayerSource(), other.getDataLayerSource())) {
			return false;
		}
		if (one.getDataLayerType() != other.getDataLayerType()) {
			return false;
		}
		if (one.getDataLayerVirtualLan() != other.getDataLayerVirtualLan()) {
			return false;
		}
		if (one.getDataLayerVirtualLanPriorityCodePoint() != other
				.getDataLayerVirtualLanPriorityCodePoint()) {
			return false;
		}
		if (one.getNetworkDestination() != other.getNetworkDestination()) {
			return false;
		}
		if (one.getNetworkProtocol() != other.getNetworkProtocol()) {
			return false;
		}
		if (one.getNetworkSource() != other.getNetworkSource()) {
			return false;
		}
		if (one.getNetworkTypeOfService() != other.getNetworkTypeOfService()) {
			return false;
		}
		if (one.getTransportDestination() != other.getTransportDestination()) {
			return false;
		}
		if (one.getTransportSource() != other.getTransportSource()) {
			return false;
		}
		if ((one.getWildcards() & OFMatch.OFPFW_ALL) != (other.getWildcards() & OFMatch.OFPFW_ALL)) { // only
			// consider
			// allocated
			// part
			// of
			// wildcards
			return false;
		}
		return true;
	}
}
