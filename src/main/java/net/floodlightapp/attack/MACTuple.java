package net.floodlightapp.attack;

import net.floodlightcontroller.util.MACAddress;

public class MACTuple {
	private MACAddress src;
	private MACAddress dst;

	public MACTuple(MACAddress src, MACAddress dst) {
		this.src = src;
		this.dst = dst;
	}

	public MACAddress getSrc() {
		return src;
	}

	public MACAddress getDst() {
		return dst;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		} else if (!(obj instanceof MACTuple)) {
			return false;
		} else {
			return this.src.equals(((MACTuple) obj).src)
					&& this.dst.equals(((MACTuple) obj).dst);
		}
	}

	@Override
	public int hashCode() {
		final int prime = 2521;
		int result = 1;
		result = prime * result + src.hashCode();
		result = prime * result + dst.hashCode();
		return result;
	}

	public String toString() {
		String s = "";
		s += src + "->" + dst;
		return s;
	}
}