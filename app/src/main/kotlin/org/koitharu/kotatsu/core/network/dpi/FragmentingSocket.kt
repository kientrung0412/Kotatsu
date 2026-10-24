package org.koitharu.kotatsu.core.network.dpi

import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.Socket
import java.net.SocketAddress
import java.nio.channels.SocketChannel

/**
 * Delegating [Socket] which fragments the first outgoing TLS record (the ClientHello).
 */
internal class FragmentingSocket(
	private val delegate: Socket,
	private val host: String?,
) : Socket() {

	private val outputStream by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
		FragmentingOutputStream(delegate.getOutputStream(), host)
	}

	override fun getOutputStream(): OutputStream = outputStream

	override fun getInputStream(): InputStream = delegate.getInputStream()

	override fun connect(endpoint: SocketAddress?) = delegate.connect(endpoint)

	override fun connect(endpoint: SocketAddress?, timeout: Int) = delegate.connect(endpoint, timeout)

	override fun bind(bindpoint: SocketAddress?) = delegate.bind(bindpoint)

	override fun getInetAddress(): InetAddress? = delegate.inetAddress

	override fun getLocalAddress(): InetAddress = delegate.localAddress

	override fun getPort(): Int = delegate.port

	override fun getLocalPort(): Int = delegate.localPort

	override fun getRemoteSocketAddress(): SocketAddress? = delegate.remoteSocketAddress

	override fun getLocalSocketAddress(): SocketAddress? = delegate.localSocketAddress

	override fun getChannel(): SocketChannel? = delegate.channel

	override fun setTcpNoDelay(on: Boolean) {
		delegate.tcpNoDelay = on
	}

	override fun getTcpNoDelay(): Boolean = delegate.tcpNoDelay

	override fun setSoLinger(on: Boolean, linger: Int) = delegate.setSoLinger(on, linger)

	override fun getSoLinger(): Int = delegate.soLinger

	override fun sendUrgentData(data: Int) = delegate.sendUrgentData(data)

	override fun setOOBInline(on: Boolean) {
		delegate.oobInline = on
	}

	override fun getOOBInline(): Boolean = delegate.oobInline

	override fun setSoTimeout(timeout: Int) {
		delegate.soTimeout = timeout
	}

	override fun getSoTimeout(): Int = delegate.soTimeout

	override fun setSendBufferSize(size: Int) {
		delegate.sendBufferSize = size
	}

	override fun getSendBufferSize(): Int = delegate.sendBufferSize

	override fun setReceiveBufferSize(size: Int) {
		delegate.receiveBufferSize = size
	}

	override fun getReceiveBufferSize(): Int = delegate.receiveBufferSize

	override fun setKeepAlive(on: Boolean) {
		delegate.keepAlive = on
	}

	override fun getKeepAlive(): Boolean = delegate.keepAlive

	override fun setTrafficClass(tc: Int) {
		delegate.trafficClass = tc
	}

	override fun getTrafficClass(): Int = delegate.trafficClass

	override fun setReuseAddress(on: Boolean) {
		delegate.reuseAddress = on
	}

	override fun getReuseAddress(): Boolean = delegate.reuseAddress

	override fun close() = delegate.close()

	override fun shutdownInput() = delegate.shutdownInput()

	override fun shutdownOutput() = delegate.shutdownOutput()

	override fun isConnected(): Boolean = delegate.isConnected

	override fun isBound(): Boolean = delegate.isBound

	override fun isClosed(): Boolean = delegate.isClosed

	override fun isInputShutdown(): Boolean = delegate.isInputShutdown

	override fun isOutputShutdown(): Boolean = delegate.isOutputShutdown

	override fun toString(): String = "FragmentingSocket[$delegate]"
}
