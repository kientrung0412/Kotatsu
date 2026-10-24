package org.koitharu.kotatsu.core.network.dpi

import java.io.FilterOutputStream
import java.io.OutputStream

/**
 * Splits the first written TLS handshake record into two TLS records, each one sent in its own TCP segment.
 * The split point is placed in the middle of the server name, so the SNI never appears in a single packet.
 */
internal class FragmentingOutputStream(
	out: OutputStream,
	host: String?,
) : FilterOutputStream(out) {

	private val hostBytes = host?.takeIf { it.isNotEmpty() }?.toByteArray(Charsets.US_ASCII)
	private var isFragmented = false

	override fun write(b: Int) = write(byteArrayOf(b.toByte()), 0, 1)

	override fun write(b: ByteArray) = write(b, 0, b.size)

	@Synchronized
	override fun write(b: ByteArray, off: Int, len: Int) {
		if (isFragmented || len <= 0) {
			out.write(b, off, len)
			return
		}
		isFragmented = true
		for (chunk in fragment(b, off, len, hostBytes)) {
			out.write(chunk)
			out.flush()
		}
	}

	companion object {

		private const val RECORD_HEADER_SIZE = 5
		private const val CONTENT_TYPE_HANDSHAKE: Byte = 0x16

		fun fragment(b: ByteArray, off: Int, len: Int, host: ByteArray?): List<ByteArray> {
			if (len < RECORD_HEADER_SIZE + 2 || b[off] != CONTENT_TYPE_HANDSHAKE || b[off + 1] != 0x03.toByte()) {
				return listOf(b.copyOfRange(off, off + len))
			}
			val bodyStart = off + RECORD_HEADER_SIZE
			val recordLength = ((b[off + 3].toInt() and 0xFF) shl 8) or (b[off + 4].toInt() and 0xFF)
			if (recordLength < 2 || RECORD_HEADER_SIZE + recordLength > len) {
				// incomplete record, fallback to TCP-level split only
				val point = splitPoint(b, off, len, host).coerceIn(1, len - 1)
				return listOf(b.copyOfRange(off, off + point), b.copyOfRange(off + point, off + len))
			}
			val point = (splitPoint(b, bodyStart, recordLength, host)).coerceIn(1, recordLength - 1)
			val first = ByteArray(RECORD_HEADER_SIZE + point)
			System.arraycopy(b, off, first, 0, 3)
			first.putLength(point)
			System.arraycopy(b, bodyStart, first, RECORD_HEADER_SIZE, point)
			val tailLength = len - RECORD_HEADER_SIZE - point
			val second = ByteArray(RECORD_HEADER_SIZE + tailLength)
			System.arraycopy(b, off, second, 0, 3)
			second.putLength(recordLength - point)
			System.arraycopy(b, bodyStart + point, second, RECORD_HEADER_SIZE, tailLength)
			return listOf(first, second)
		}

		private fun ByteArray.putLength(value: Int) {
			this[3] = (value shr 8).toByte()
			this[4] = value.toByte()
		}

		/**
		 * @return offset relative to [start] pointing to the middle of the host name or the middle of the data
		 */
		private fun splitPoint(b: ByteArray, start: Int, len: Int, host: ByteArray?): Int {
			if (host != null) {
				val index = indexOf(b, start, len, host)
				if (index >= 0) {
					return index + maxOf(1, host.size / 2)
				}
			}
			return len / 2
		}

		private fun indexOf(b: ByteArray, start: Int, len: Int, target: ByteArray): Int {
			val last = len - target.size
			outer@ for (i in 0..last) {
				for (j in target.indices) {
					if (b[start + i + j] != target[j]) {
						continue@outer
					}
				}
				return i
			}
			return -1
		}
	}
}
