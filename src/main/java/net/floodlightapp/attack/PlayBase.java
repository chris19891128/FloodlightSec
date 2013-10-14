package net.floodlightapp.attack;

import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumSet;
import java.util.Map;

import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFType;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.counter.ICounterStoreService;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.routing.IRoutingService;
import net.floodlightcontroller.staticflowentry.IStaticFlowEntryPusherService;
import net.floodlightcontroller.topology.ITopologyService;
import net.floodlightcontroller.util.OFMessageDamper;
/**
 * 
 * @author shichao
 *
 */
public abstract class PlayBase implements IFloodlightModule, IOFMessageListener {

	protected IFloodlightProviderService floodlightProvider;
	protected ITopologyService topologyManager;
	protected IRoutingService routingEngine;
	protected IDeviceService deviceManager;
	protected ICounterStoreService counterStore;
	protected IStaticFlowEntryPusherService flowPusher;
	protected OFMessageDamper messageDamper;

	protected static int OFMESSAGE_DAMPER_CAPACITY = 50000; // TODO: find sweet spot
    protected static int OFMESSAGE_DAMPER_TIMEOUT = 250; // ms 
    
	@Override
	public String getName() {
		return null;
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> collection = new ArrayList<Class<? extends IFloodlightService>>();
		collection.add(IFloodlightProviderService.class);
		collection.add(ITopologyService.class);
		collection.add(IRoutingService.class);
		collection.add(IDeviceService.class);
		collection.add(ICounterStoreService.class);
		collection.add(IStaticFlowEntryPusherService.class);
		return collection;
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		this.floodlightProvider = context
				.getServiceImpl(IFloodlightProviderService.class);
		this.topologyManager = context.getServiceImpl(ITopologyService.class);
		this.routingEngine = context.getServiceImpl(IRoutingService.class);
		this.deviceManager = context.getServiceImpl(IDeviceService.class);
		this.counterStore = context.getServiceImpl(ICounterStoreService.class);
		this.flowPusher = context
				.getServiceImpl(IStaticFlowEntryPusherService.class);
		this.messageDamper = new OFMessageDamper(OFMESSAGE_DAMPER_CAPACITY,
				EnumSet.of(OFType.FLOW_MOD), OFMESSAGE_DAMPER_TIMEOUT);
	}

	@Override
	public void startUp(FloodlightModuleContext context) {
		// TODO Auto-generated method stub

	}

}
