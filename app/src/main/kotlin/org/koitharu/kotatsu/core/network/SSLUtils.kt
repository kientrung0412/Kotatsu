package org.koitharu.kotatsu.core.network

import android.annotation.SuppressLint
import android.content.Context
import android.content.res.AssetManager
import android.util.Log
import okhttp3.OkHttpClient
import org.conscrypt.Conscrypt
import okhttp3.tls.HandshakeCertificates
import org.koitharu.kotatsu.BuildConfig
import org.koitharu.kotatsu.core.network.dpi.DpiBypassSSLSocketFactory
import org.koitharu.kotatsu.core.util.ext.printStackTraceDebug
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.X509TrustManager

@SuppressLint("CustomX509TrustManager")
fun OkHttpClient.Builder.disableCertificateVerification(isDpiBypassEnabled: Boolean) = also { builder ->
	runCatching {
		val trustAllCerts = object : X509TrustManager {
			override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) = Unit

			override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) = Unit

			override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
		}
		val sslSocketFactory: SSLSocketFactory = if (isDpiBypassEnabled) {
			createDpiBypassSocketFactory(trustAllCerts)
		} else {
			null
		} ?: SSLContext.getInstance("SSL").also {
			it.init(null, arrayOf(trustAllCerts), SecureRandom())
		}.socketFactory
		builder.sslSocketFactory(sslSocketFactory, trustAllCerts)
		builder.hostnameVerifier { _, _ -> true }
	}.onFailure {
		it.printStackTraceDebug()
	}
}

fun OkHttpClient.Builder.installExtraCertificates(context: Context, isDpiBypassEnabled: Boolean) = also { builder ->
	val certificatesBuilder = HandshakeCertificates.Builder()
		.addPlatformTrustedCertificates()
	val assets = context.assets.list("").orEmpty()
	for (path in assets) {
		if (path.endsWith(".pem")) {
			val cert = loadCert(context, path) ?: continue
			certificatesBuilder.addTrustedCertificate(cert)
		}
	}
	val certificates = certificatesBuilder.build()
	val sslSocketFactory = if (isDpiBypassEnabled) {
		createDpiBypassSocketFactory(certificates.trustManager)
	} else {
		null
	} ?: certificates.sslSocketFactory()
	builder.sslSocketFactory(sslSocketFactory, certificates.trustManager)
}

private fun createDpiBypassSocketFactory(trustManager: X509TrustManager): SSLSocketFactory? = runCatching {
	val sslContext = SSLContext.getInstance("TLS", Conscrypt.newProvider())
	sslContext.init(null, arrayOf(trustManager), SecureRandom())
	DpiBypassSSLSocketFactory(sslContext.socketFactory)
}.onFailure { e ->
	e.printStackTraceDebug()
}.getOrNull()

private fun loadCert(context: Context, path: String): X509Certificate? = runCatching {
	val cf = CertificateFactory.getInstance("X.509")
	context.assets.open(path, AssetManager.ACCESS_STREAMING).use {
		cf.generateCertificate(it)
	} as X509Certificate
}.onFailure { e ->
	e.printStackTraceDebug()
}.onSuccess {
	if (BuildConfig.DEBUG) {
		Log.i("ExtraCerts", "Loaded cert $path")
	}
}.getOrNull()
