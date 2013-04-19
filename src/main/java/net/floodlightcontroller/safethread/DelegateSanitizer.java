package net.floodlightcontroller.safethread;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.openflow.protocol.OFMessage;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.internal.Controller;
import net.floodlightcontroller.core.internal.OFSwitchImpl;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.counter.ICounterStoreService;
import net.floodlightcontroller.restserver.IRestApiService;
import net.floodlightcontroller.safethread.message.ApiRequest;
import net.floodlightcontroller.util.QueueWriter;

/**
 * Generate proxy objects from real objects.
 * 
 * @author Xitao Wen
 * 
 */
public class DelegateSanitizer {
	private final Map<Long, Object> id2ObjectMap; // Shared with KernelDeputy
												  // DelegateSanitizer is the only place inserting
												  // items in to this map.
	private final Map<Long, Object> id2DelegateMap;// Should be synced with id2ObjectMap 
													// all the time.
	private final Map<Pair<Object,FloodlightModuleRunnable>, Long> object2IdMap; // Should be synced
																// with id2ObjectMap all the time.
	private final QueueWriter<ApiRequest> apiRequestQueueWriter; // Shared with KernelDeputy
	
	private long idBase;

	class Pair<A, B> {
	    private A first;
	    private B second;

	    public Pair(A first, B second) {
	    	super();
	    	this.first = first;
	    	this.second = second;
	    }

	    public int hashCode() {
	    	int hashFirst = first != null ? first.hashCode() : 0;
	    	int hashSecond = second != null ? second.hashCode() : 0;

	    	return (hashFirst + hashSecond) * hashSecond + hashFirst;
	    }

	    public boolean equals(Object other) {
	    	if (other instanceof Pair) {
	    		@SuppressWarnings("rawtypes")
				Pair otherPair = (Pair) other;
	    		return 
	    		((  this.first == otherPair.first ||
	    			( this.first != null && otherPair.first != null &&
	    			  this.first.equals(otherPair.first))) &&
	    		 (	this.second == otherPair.second ||
	    			( this.second != null && otherPair.second != null &&
	    			  this.second.equals(otherPair.second))) );
	    	}

	    	return false;
	    }

	    public String toString()
	    { 
	           return "(" + first + ", " + second + ")"; 
	    }

	    public A getFirst() {
	    	return first;
	    }

	    public void setFirst(A first) {
	    	this.first = first;
	    }

	    public B getSecond() {
	    	return second;
	    }

	    public void setSecond(B second) {
	    	this.second = second;
	    }
	}
	
	public DelegateSanitizer(Map<Long, Object> idMap, QueueWriter<ApiRequest> qw) {
		this.id2ObjectMap = idMap;
		this.apiRequestQueueWriter = qw;
		this.id2DelegateMap = new HashMap<Long, Object>();
		this.object2IdMap = new HashMap<Pair<Object, FloodlightModuleRunnable>, Long>();
	}
	
	/**
	 * Caller has to ensure no conflict.
	 * @param obj
	 * @param app
	 * @return
	 */
	private Long insertObject(long id, Object obj, Object delegate, FloodlightModuleRunnable app) {
		this.id2ObjectMap.put(id, obj);
		this.id2DelegateMap.put(id, delegate);
		this.object2IdMap.put(new Pair<Object, FloodlightModuleRunnable>(obj, app), id);
		return id;
	}
	
	private Long getIdWithObject(Object obj, FloodlightModuleRunnable app) {
		return this.object2IdMap.get(new Pair<Object, FloodlightModuleRunnable>(obj, app));
	}
	
	private Object getObject(Long id) {
		return this.id2ObjectMap.get(id);
	}
	
	/**
	 * Look up delegate with id
	 * @param id
	 * @return
	 */
	private Object getDelegate(Long id) {
		return this.id2DelegateMap.get(id);
	}

	public FloodlightProviderDelegate getFloodlightProviderDelegate(
			IFloodlightProviderService iprovider, FloodlightModuleRunnable app) {
		FloodlightProviderDelegate delegate;
		
		if (iprovider instanceof FloodlightProviderDelegate) {
			iprovider = (IFloodlightProviderService) this.getObject(
					((FloodlightProviderDelegate) iprovider).getObjectId());
		} else if (!(iprovider instanceof Controller))
			return null;

		Long id = getIdWithObject(iprovider, app);
		if (id==null) {
			// no hit
			id = idBase++;
			delegate = new FloodlightProviderDelegate(
					id, app, this.apiRequestQueueWriter);
			this.insertObject(id, iprovider, delegate, app);
		} else {
			// hit
			delegate = (FloodlightProviderDelegate) this.getDelegate(id);
		}
		
		return delegate;
	}

	public FloodlightModuleContext getFloodlightModuleContextDelegate(
			FloodlightModuleContext cntx, FloodlightModuleRunnable app) {
		FloodlightModuleContext ret = new FloodlightModuleContext();

		Collection<Class<? extends IFloodlightService>> servs = app
				.getModuleDependencies();
		for (Class<? extends IFloodlightService> s : servs) {
			ret.addService(s, this.sanitize(cntx.getServiceImpl(s), app));
		}

		return ret;
	}

	public IFloodlightService sanitize(IFloodlightService s,
			FloodlightModuleRunnable app) {
		if (s instanceof IFloodlightProviderService) {
			return this.getFloodlightProviderDelegate(
					(IFloodlightProviderService) s, app);
		} 
		else if (s instanceof ICounterStoreService) {
			// Pass through CounterStoreService 
			return s;
		}
		else if (s instanceof IRestApiService) {
			// Pass through REST service for now
			// Monitor REST resources in the future
			return s;
		}
		else {
			return null;
		}
	}

	public IOFSwitch getOFSwitchDelegate(IOFSwitch sw,
			FloodlightModuleRunnable app) {
		if (sw instanceof OFSwitchDelegate) {
			sw = (IOFSwitch) this.getObject(((OFSwitchDelegate) sw)
					.getObjectId());
		} else if (!(sw instanceof OFSwitchImpl))
			return null;

		OFSwitchDelegate delegate;
		Long id = getIdWithObject(sw, app);
		if (id==null) {
			// no hit
			id = idBase++;
			delegate = new OFSwitchDelegate(id, app,
					this.apiRequestQueueWriter);
			this.insertObject(id, sw, delegate, app);
		} else {
			// hit
			delegate = (OFSwitchDelegate) this.getDelegate(id);
		}
		
		return delegate;
	}

	public OFMessage sanitizeOFMessage(OFMessage msg,
			FloodlightModuleRunnable app) {
		// TODO Sanitize msg according to policy
		return msg;
	}

	public FloodlightContext sanitizeFloodlightContext(FloodlightContext cntx,
			FloodlightModuleRunnable app) {
		// TODO This one seems hard to deal with. There's no easy way to determine 
		// what sensitive info is in it.
		return cntx;
	}

}
