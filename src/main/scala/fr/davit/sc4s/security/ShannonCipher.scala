package fr.davit.sc4s.security

import scodec.bits.BitVector
import scodec.codecs._
import sun.security.util.SecurityConstants

import java.lang.Integer._
import java.security._
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.{AEADBadTagException, Cipher, CipherSpi, NoSuchPaddingException}
import scala.collection.mutable
import scala.util.chaining._

object ShannonCipher {

  // Value of konst to use during key loading
  val InitKonst = 0x6996c53a
  // Register initialized to Fibonacci numbers
  val InitVector: Array[Int] = Array(1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 377, 610, 987)
  // Where to insert key/MAC/counter words
  val KeyPosition = 13
  // Word size
  val BlockSize = 4

  final case class NonceParameterSpec(nonce: Int) extends AlgorithmParameterSpec

  object ShannonCipherProvider
      extends Provider("ShannonCipherProvider", SecurityConstants.PROVIDER_VER, "Shannon stream-cipher") {
    put("Cipher.Shannon", classOf[ShannonCipher].getCanonicalName)
  }
}

class ShannonCipher extends CipherSpi {

  import ShannonCipher._

  private var decrypting: Boolean            = false
  private var nonce: Int                     = 0

  // Working storage for the shift register
  private val register: Array[Int] = Array.ofDim[Int](16)
  // Working storage for crc accumulation
  private val crc: Array[Int] = Array.ofDim[Int](16)
  // IV
  private val iv: Array[Int] = Array.ofDim[Int](16)

  // Key dependant semi-constant
  private var k: Int = InitKonst

  // Partial word MAC buffer
  private val macBuffer: mutable.Queue[Byte] = mutable.Queue.empty[Byte]
  // Encryption buffer
  private val encryptionBuffer: mutable.Queue[Byte] = mutable.Queue.empty[Byte]

  // Modes do not make sense with stream ciphers, but allow ECB
  // see JCE spec.
  override def engineSetMode(mode: String): Unit = {
    if (!mode.equalsIgnoreCase("ECB")) throw new NoSuchAlgorithmException("Unsupported mode " + mode)
  }

  // Padding does not make sense with stream ciphers, but allow NoPadding
  // see JCE spec.
  override def engineSetPadding(padding: String): Unit = {
    if (!padding.equalsIgnoreCase("NoPadding")) throw new NoSuchPaddingException("Unsupported padding " + padding)
  }

  // Return 0 to indicate stream cipher
  // see JCE spec.
  override def engineGetBlockSize(): Int = 0

  override def engineGetOutputSize(inputLen: Int): Int = if (decrypting) inputLen - BlockSize else inputLen + BlockSize

  override def engineGetIV(): Array[Byte] = iv.map(int32L.encode).map(_.require.toByteVector).reduce(_ ++ _).toArray

  override def engineGetParameters(): AlgorithmParameters = null

  override def engineInit(opmode: Int, key: Key, random: SecureRandom): Unit = init(opmode, key, 0)

  override def engineInit(opmode: Int, key: Key, params: AlgorithmParameterSpec, random: SecureRandom): Unit = {
    val nonce = Option(params) match {
      case None                        => 0
      case Some(NonceParameterSpec(n)) => n
      case Some(_)                     => throw new InvalidAlgorithmParameterException("Parameters not supported")
    }
    init(opmode, key, nonce)
  }

  override def engineInit(opmode: Int, key: Key, params: AlgorithmParameters, random: SecureRandom): Unit = {
    if (params != null) throw new InvalidAlgorithmParameterException("Parameters not supported")
    init(opmode, key, 0)
  }

  private def init(opmode: Int, key: Key, nonce: Int): Unit = {
    opmode match {
      case Cipher.DECRYPT_MODE => decrypting = true
      case Cipher.ENCRYPT_MODE => decrypting = false
      case _                   => new UnsupportedOperationException("Mode must be ENCRYPT_MODE or DECRYPT_MODE")
    }
    if (key.getAlgorithm != "Shannon") throw new InvalidKeyException(s"Not an Shannon key: ${key.getAlgorithm}")
    if (key.getFormat != "RAW") throw new InvalidKeyException("Key encoding format must be RAW")
    this.nonce = nonce
    generateIv(key.getEncoded)
    nonceAndIncrement()
  }

  private def generateIv(data: Array[Byte]): Unit = {
    k = InitKonst
    InitVector.copyToArray(register)
    load(data)
    register.copyToArray(iv)
  }

  private def nonceAndIncrement(): Unit = {
    k = InitKonst
    iv.copyToArray(register)
    val data = int32L.encode(nonce).require.toByteVector.toArray
    load(data)
    k = register.head
    nonce += 1
  }

  // Load key material into the register
  private def addKeyBlock(block: Int): Unit = {
    register(KeyPosition) = register(KeyPosition) ^ block
    step()
  }

  private def load(data: Array[Byte]): Unit = {
    // Start folding data
    data
      .grouped(4)
      .map(_.padTo(4, 0.toByte))
      .map(BitVector.apply)
      .map(int32L.decode)
      .map(_.require.value)
      .foreach(addKeyBlock)
    // Also fold in the length of the data
    addKeyBlock(data.length)
    // Save a copy of the register
    register.copyToArray(crc)
    // Now diffuse
    diffuse()
    // Now XOR the copy back -- makes key loading irreversible
    crcXor()
  }

  // Nonlinear transform (sbox) of a word. There are two slightly different combinations
  private def transform(d1: Int, d2: Int)(i: Int): Int = i ^ (rotateLeft(i, d1) | rotateLeft(i, d2))
  private def sbox1(i: Int): Int                       = i.pipe(transform(5, 7)).pipe(transform(19, 22))
  private def sbox2(i: Int): Int                       = i.pipe(transform(7, 22)).pipe(transform(5, 19))

  private def step(): Int = {
    // Nonlinear feedback function
    val last = sbox1(register(12) ^ register(13) ^ k) ^ rotateLeft(register(0), 1)
    // Shift register
    Array.copy(register, 1, register, 0, 15)
    register(15) = last

    val head = sbox2(register(2) ^ register(15))
    register(0) = register(0) ^ head

    head ^ register(8) ^ register(12)
  }

  // Extra nonlinear diffusion of register for key and MAC
  private def diffuse(): Unit = (0 until 16).foreach(_ => step())

  // consume the key stream
  private def getKeyStreamByte(): Byte = {
    if (encryptionBuffer.isEmpty) {
      val key   = step()
      val bytes = int32L.encode(key).require.toByteArray
      encryptionBuffer.enqueueAll(bytes)
    }
    encryptionBuffer.dequeue()
  }

  // Accumulate a crc of input words, later to be fed into MAC.
  // This is actually 32 parallel crc-16s, using the IBM crc-16
  // polynomian x^16 + x^15 + x^2 + 1
  private def crcUpdate(i: Int): Unit = {
    val last = crc(0) ^ crc(2) ^ crc(15) ^ i
    // Shift crc
    Array.copy(crc, 1, crc, 0, 15)
    crc(15) = last
  }

  private def crcXor(): Unit = {
    register.indices.foreach(i => register(i) = register(i) ^ crc(i))
  }

  // Normal MAC word processing: do both stream register and CRC
  private def macUpdate(byte: Byte): Unit = {
    macBuffer.enqueue(byte)
    if (macBuffer.size == BlockSize) {
      val block = int32L.decode(BitVector(macBuffer)).require.value
      macBuffer.clear()
      crcUpdate(block)
      register(KeyPosition) = register(KeyPosition) ^ block
    }
  }

  override def engineUpdate(input: Array[Byte], inputOffset: Int, inputLen: Int): Array[Byte] = {
    val output = Array.ofDim[Byte](inputLen)
    engineUpdate(input, inputOffset, inputLen, output, 0)
    output
  }

  override def engineUpdate(
      input: Array[Byte],
      inputOffset: Int,
      inputLen: Int,
      output: Array[Byte],
      outputOffset: Int
  ): Int = {
    crypt(input, inputOffset, inputLen, output, outputOffset)
    inputLen
  }

  private def crypt(
      input: Array[Byte],
      inputOffset: Int,
      inputLen: Int,
      output: Array[Byte],
      outputOffset: Int
  ): Unit = {
    (0 until inputLen).foreach { i =>
      val inputByte = input(inputOffset + i)
      val byte      = (inputByte ^ getKeyStreamByte()).toByte
      output(outputOffset + i) = byte
      // plaintext is accumulated for MAC
      if (decrypting) macUpdate(byte) else macUpdate(inputByte)
    }
  }

  override def engineDoFinal(input: Array[Byte], inputOffset: Int, inputLen: Int): Array[Byte] = {
    val output = Array.ofDim[Byte](engineGetOutputSize(inputLen))
    engineDoFinal(input, inputOffset, inputLen, output, 0)
    output
  }

  override def engineDoFinal(
      input: Array[Byte],
      inputOffset: Int,
      inputLen: Int,
      output: Array[Byte],
      outputOffset: Int
  ): Int = {
    val payloadLen = if (decrypting) inputLen - BlockSize else inputLen
    crypt(input, inputOffset, payloadLen, output, outputOffset)

    // Handle any previously buffered bytes
    while (macBuffer.nonEmpty) macUpdate(0.toByte)

    // Perturb the MAC to mark end of input.
    // Note that only the stream register is updated, not the CRC.
    // This is an action that can't be duplicated by passing in plaintext,
    // hence defeating any kind of extension attack.
    step()
    register(13) = register(13) ^ (InitKonst ^ (encryptionBuffer.size * 8) << 3)
    encryptionBuffer.clear()
    // Now add the CRC to the stream register and diffuse it
    crcXor()
    diffuse()

    val size = if (decrypting) {
      val end = inputLen - BlockSize
      // Verify tag
      (end until inputLen).foreach { i =>
        if (input(i) != getKeyStreamByte()) throw new AEADBadTagException("Tag mismatch")
      }
      inputLen - BlockSize
    } else {
      val end = outputOffset + inputLen
      // Put the MAC into the output
      (end until end + BlockSize).foreach { i =>
        output(i) = getKeyStreamByte()
      }
      inputLen + BlockSize
    }

    // prepare for next stream message
    nonceAndIncrement()
    size
  }
}
