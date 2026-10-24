package org.koitharu.kotatsu.core.network.dpi

import org.conscrypt.Conscrypt
import java.net.InetAddress
import java.net.Socket
import javax.net.ssl.SSLSocketFactory

/**
 * Wraps a Conscrypt [SSLSocketFactory] so that the TLS ClientHello is split into several
 * TLS records and TCP segments. This hides the SNI from naive DPI middleboxes.
 */
class DpiBypassSSLSocketFactory(
	private val delegate: SSLSocketFactory,
) : SSLSocketFactory() {

	init {
		// Engine socket writes through the wrapped socket streams instead of the file descriptor
		if (Conscrypt.isConscrypt(delegate)) {
			Conscrypt.setUseEngineSocket(delegate, true)
		}
	}

	override fun getDefaultCipherSuites(): Array<String> = delegate.defaultCipherSuites

	override fun getSupportedCipherSuites(): Array<String> = delegate.supportedCipherSuites

	override fun createSocket(s: Socket, host: String?, port: Int, autoClose: Boolean): Socket {
		runCatching { s.tcpNoDelay = true }
		return delegate.createSocket(FragmentingSocket(s, host), host, port, autoClose)
	}

	override fun createSocket(host: String, port: Int): Socket {
		return createSocket(Socket(host, port), host, port, true)
	}

	override fun createSocket(host: String, port: Int, localHost: InetAddress?, localPort: Int): Socket {
		return createSocket(Socket(host, port, localHost, localPort), host, port, true)
	}

	override fun createSocket(host: InetAddress, port: Int): Socket {
		return createSocket(Socket(host, port), host.hostName, port, true)
	}

	override fun createSocket(address: InetAddress, port: Int, localAddress: InetAddress?, localPort: Int): Socket {
		return createSocket(Socket(address, port, localAddress, localPort), address.hostName, port, true)
	}
}
