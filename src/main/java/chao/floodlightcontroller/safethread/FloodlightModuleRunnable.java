package chao.floodlightcontroller.safethread;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;

import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFType;

/**
 * This is the class for the sub-coordinated thread model. The AppThread is the
 * bed where the module is embedded. However, for the module, this AppThread
 * should be transparent.
 * 
 * The AppThread will maintain a list of proxy service implementation and the
 * module is referencing them. However, it can referencing the kernel space
 * components.
 * 
 * @author shichao
 * 
 */
public class FloodlightModuleRunnable implements Runnable, IOFMessageListener {
	private final IFloodlightModule module;
	// TODO Field to be removed
	public FloodlightModuleContext realContext;
	private final FloodlightModuleContext virtualContext;

	private Queue<ApiRequest> request_queue;// On the kernel side
	private Queue<ApiResponse> response_queue;
	private Queue<OFMessageInfo> ofm_queue;
	private Map<OFType, List<IOFMessageListener>> map;

	private Object apiResponseMonitor;
	private Object ofMessageMonitor;

	/**
	 * (1) Every AppThread will have a map of proxy service implementation in
	 * the AppThread space (user space) which will delegate the module for the
	 * API calls related to this service. On the contrary, the real service
	 * implementation will lie in the SecurityThread (kernel space). The proxy
	 * service implementation will do nothing else but to pass the call to the
	 * real implemenation through the queue we define.
	 * 
	 * (2) There is no need to change the module part except for the init()
	 * method. We will give a "illusion context" to the module making him
	 * believe that he is still referencing those real service implementation.
	 * But actually he is simply referencing those proxy service implementation.
	 * 
	 * 
	 * @param service
	 *            the type of service implemented
	 * @param impl
	 *            the proxy service implementation
	 * 
	 * @return The boolean value indicating whether the addition is successful
	 *         or not. The addition will fail if the proxy service
	 *         implementation providing that service is already in use
	 * 
	 */

	public FloodlightModuleRunnable(IFloodlightModule module) {
		this.module = module;
		virtualContext = new FloodlightModuleContext();
		for (Class<? extends IFloodlightService> clazz : module
				.getModuleDependencies()) {
			virtualContext.addService(clazz,
					ProxyServiceImplFactory.instance(clazz, this));
		}
		request_queue = new ConcurrentLinkedQueue<ApiRequest>();
		response_queue = new ConcurrentLinkedQueue<ApiResponse>();
		ofm_queue = new ConcurrentLinkedQueue<OFMessageInfo>();
		apiResponseMonitor = new Object();
		ofMessageMonitor = new Object();
	}

	private IFloodlightModule getModule() {
		return module;
	}
	
	private String getModuleName(){
		return module.getClass().getCanonicalName();
	}

	/**
	 * Method for initialize the module with your crafted context. Make sure
	 * that it is called after setting the module
	 */
	public void initModule() {
		try {
			module.init(virtualContext);
		} catch (FloodlightModuleException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	/**
	 * To be deprecated
	 * 
	 * @param realContext
	 */
	public void initModule(FloodlightModuleContext realContext) {
		this.realContext = realContext;
		initModule();
	}

	public void startModule() {
		module.startUp(virtualContext);
	}

	public void writeRequestToQueue(ApiRequest req) {
		request_queue.add(req);
	}

	/**
	 * This function is waiting on the response queue until it is not empty
	 * 
	 * @return Always return true
	 */
	public boolean waitResponseFromQueue() {
		while (response_queue.isEmpty()) {
			synchronized (apiResponseMonitor) {
				try {
					apiResponseMonitor.wait();
				} catch (InterruptedException e) {
					System.err.println("Read response from queue interrupted");
					e.printStackTrace();
				}
			}
		}
		return true;
	}

	/**
	 * This function will wait on the queue for a maximum of n seconds. If the
	 * queue is ready for reading by that time, return the true, else return
	 * false.
	 * 
	 * @param n
	 *            Patience Time in seconds. 0 means no timeout, same as
	 *            waitResponseFromQueue()
	 * @return True if the queue is ready for read and false if timeout
	 */
	public boolean waitResponseFromQueue(int n) {

		if (n == 0) {
			return waitResponseFromQueue();
		}

		long start = System.currentTimeMillis();
		while (response_queue.isEmpty()
				&& System.currentTimeMillis() - start < n * 1000) {
			synchronized (apiResponseMonitor) {
				try {
					apiResponseMonitor.wait(1000);
				} catch (InterruptedException e) {
					System.err.println("Read response from queue interrupted");
					e.printStackTrace();
				}
			}
		}
		if (!response_queue.isEmpty()) {
			return true;
		} else {
			return false;
		}
	}

	/**
	 * This non-blocking function will read from response queue, and return null
	 * if the queue is empty
	 * 
	 * @return
	 */
	public ApiResponse peekResponseFromQueue() {
		if (response_queue.isEmpty()) {
			return null;
		}
		return response_queue.poll();
	}

	/**
	 * This blocking function will read from the response queue until successful
	 * 
	 * @return The API call response
	 */
	public ApiResponse readResponseFromQueue() {
		this.waitResponseFromQueue();
		return response_queue.poll();
	}

	/**
	 * This blocking function will read from the response queue until successful
	 * or timeout
	 * 
	 * @param n
	 *            Timeout value
	 * @return The API call response
	 */
	public ApiResponse readResponseFromQueue(int n) {
		if (waitResponseFromQueue(n)) {
			return response_queue.poll();
		} else {
			return null;
		}
	}

	public void notifyResponseQueue() {
		synchronized (apiResponseMonitor) {
			apiResponseMonitor.notifyAll();
		}
	}

	public boolean waitOFMessageFromQueue() {
		while (ofm_queue.isEmpty()) {
			synchronized (ofMessageMonitor) {
				try {
					ofMessageMonitor.wait();
				} catch (InterruptedException e) {
					System.err.println("Read OFMessage from queue interrupted");
					e.printStackTrace();
				}
			}
		}
		return true;
	}

	public boolean waitOFMessageFromQueue(int n) {

		if (n == 0) {
			return waitOFMessageFromQueue();
		}

		long start = System.currentTimeMillis();
		while (ofm_queue.isEmpty()
				&& System.currentTimeMillis() - start < n * 1000) {
			synchronized (ofMessageMonitor) {
				try {
					ofMessageMonitor.wait(1000);
				} catch (InterruptedException e) {
					System.err.println("Read OFMessage from queue interrupted");
					e.printStackTrace();
				}
			}
		}
		if (!ofm_queue.isEmpty()) {
			return true;
		} else {
			return false;
		}
	}

	public OFMessageInfo peekOFMessageFromQueue() {
		if (ofm_queue.isEmpty()) {
			return null;
		}
		return ofm_queue.poll();
	}

	public OFMessageInfo readOFMessageFromQueue() {
		this.waitOFMessageFromQueue();
		return ofm_queue.poll();
	}

	public OFMessageInfo readOFMessageFromQueue(int n) {
		if (waitOFMessageFromQueue(n)) {
			return ofm_queue.poll();
		} else {
			return null;
		}
	}

	public void notifyOFMessageQueue() {
		synchronized (ofMessageMonitor) {
			ofMessageMonitor.notifyAll();
		}
	}

	public void writeOFMeesgeToQueue(OFMessageInfo info) {
		ofm_queue.add(info);
		synchronized (ofMessageMonitor) {
			ofMessageMonitor.notifyAll();
		}
	}

	/**
	 * A dangerous method, called only from proxy service implementations
	 * 
	 * @param type
	 * @param listener
	 */
	public void addOFListener(OFType type, IOFMessageListener listener) {
		if (map.get(type) == null) {
			map.put(type, new ArrayList<IOFMessageListener>());
		}
		map.get(type).add(listener);
	}

	@Override
	public void run() {
		String name = this.getModuleName();
		new Thread(new OFMessageReader(), name + "-OFMeesageReader").start();
		new Thread(new ApiResponseReader(), name + "-ApiResponseReader").start();
	}

	@Override
	public String getName() {
		// The name of the module
		if (module instanceof IOFMessageListener) {
			// I robbed your name and register it to myself LOL !!!
			return ((IOFMessageListener) module).getName();
		}
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
		if (module instanceof IOFMessageListener) {
			((IOFMessageListener) module).receive(sw, msg, cntx);
		} else {
			System.err
					.println("Error, The module is not supposed to receive this OFMessage event");
		}
		return null;
	}

	private class OFMessageReader implements Runnable {

		@Override
		public void run() {
			assert (module instanceof IOFMessageListener);

			while (true) {
				OFMessageInfo info = readOFMessageFromQueue();
				System.out.println("Pop up checksum " + info.hashCode());
				IOFSwitch sw = info.getOFSwitch();
				OFMessage ofm = info.getOFMessage();
				FloodlightContext cntx = info.getFloodlightContext();
				((IOFMessageListener) module).receive(sw, ofm, cntx);
			}

		}

	}

	private class ApiResponseReader implements Runnable {

		@Override
		public void run() {
			while (true) {
				ApiResponse res = readResponseFromQueue();
				// Handle the response
			}
		}

	}

}
