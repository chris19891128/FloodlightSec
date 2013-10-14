package net.floodlightapp.attack;

import java.io.IOException;
import java.util.Collections;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;

import org.jboss.netty.buffer.ChannelBuffer;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.OFStatisticsReply;
import org.openflow.protocol.OFStatisticsRequest;
import org.openflow.protocol.OFType;
import org.openflow.protocol.OFVendor;
import org.openflow.protocol.statistics.OFFlowStatisticsReply;
import org.openflow.protocol.statistics.OFFlowStatisticsRequest;
import org.openflow.protocol.statistics.OFStatistics;
import org.openflow.protocol.statistics.OFStatisticsType;
import org.openflow.vendor.nicira.OFNiciraVendorData;
import org.openflow.vendor.nicira.OFRoleRequestVendorData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
/**
 * 
 * @author shichao
 *
 */
public class VendorSniffer extends PlayBase {

	public static Logger log = LoggerFactory.getLogger(ActiveFlowSniffer.class);

	@Override
	public String getName() {
		return "Vendor Sniffer";
	}

	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		log.info("Message recevied from switch");
		if (msg.getType() == OFType.VENDOR) {
			recvSniff(sw, msg);
		}
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
		floodlightProvider.addOFMessageListener(OFType.VENDOR, this);
		new Thread(new VendorSnifferRunnable()).start();
	}

	private class VendorSnifferRunnable implements Runnable {

		@Override
		public void run() {
			try {
				Thread.sleep(20000);
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			log.info("Will Sniff");
			proactiveVendorSniff();
			log.info("Sniff sent");
		}

	}

	private void proactiveVendorSniff() {
		IOFSwitch s1 = floodlightProvider.getSwitches().get(1l);
		if (s1 == null) {
			log.error("Too fast");
			throw new NullPointerException();
		}
		while (true) {
			try {
				Thread.sleep(1000);
				sendSniff(s1);
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}

	private void sendSniff(IOFSwitch sw) {
		OFVendor req = (OFVendor) floodlightProvider.getOFMessageFactory()
				.getMessage(OFType.VENDOR);
		OFRoleRequestVendorData roleRequestData = new OFRoleRequestVendorData();
		req.setVendorData(roleRequestData);
		req.setLengthU(OFVendor.MINIMUM_LENGTH + roleRequestData.getLength());

		try {
			messageDamper.write(sw, req, new FloodlightContext());
			sw.flush();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private void recvSniff(IOFSwitch sw, OFMessage msg) {
		if (msg.getType() == OFType.VENDOR) {
			OFVendor vendorMessage = (OFVendor) msg;
			log.info(
					"Vendor {} Version {} ",
					new Object[] { vendorMessage.getVendor(),
							vendorMessage.getVersion() });
			
		}
	}
}
