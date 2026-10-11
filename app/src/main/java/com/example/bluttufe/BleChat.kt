package com.example.bluttufe // mesmo package do MainActivity.kt

import android.annotation.SuppressLint
import android.bluetooth.*
import android.bluetooth.le.*
import android.content.Context
import android.os.*
import java.security.*
import java.security.spec.*
import java.nio.ByteBuffer
import java.util.ArrayDeque
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.*
import javax.crypto.spec.*

// UUID fixo do app. NÃO derive nada do código aqui: o que é anunciado pelo ar qualquer um escuta.
val APP_UUID: UUID = UUID.fromString("5b1a7e01-0000-4000-8000-00805f9b34fb")

/** ECDH P-256 (chaves efêmeras) + HKDF-SHA256 ligado ao código + AES-256-GCM. */
object Crypto {
    private val rnd = SecureRandom()
    fun rand(n: Int) = ByteArray(n).also { rnd.nextBytes(it) }
    fun newPair(): KeyPair = KeyPairGenerator.getInstance("EC")
        .apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    fun pub(b: ByteArray): PublicKey = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(b))
    fun hmac(k: ByteArray, vararg d: ByteArray): ByteArray = Mac.getInstance("HmacSHA256").run {
        init(SecretKeySpec(k, "HmacSHA256")); d.forEach { update(it) }; doFinal()
    }
    /** Chave do par participante<->anfitrião: segredo ECDH + código + as duas chaves públicas + nonce da conexão. */
    fun pairKey(priv: PrivateKey, peer: PublicKey, code: String, pubJ: ByteArray, pubH: ByteArray, nonce: ByteArray): ByteArray {
        val z = KeyAgreement.getInstance("ECDH").run { init(priv); doPhase(peer, true); generateSecret() }
        return try { hmac(hmac("bluttufe:$code".toByteArray(), z), pubJ, pubH, nonce, byteArrayOf(1)) }
        finally { z.fill(0) }
    }
    fun seal(k: ByteArray, p: ByteArray): ByteArray {
        val iv = rand(12)
        val c = Cipher.getInstance("AES/GCM/NoPadding")
            .apply { init(Cipher.ENCRYPT_MODE, SecretKeySpec(k, "AES"), GCMParameterSpec(128, iv)) }
        return iv + c.doFinal(p)
    }
    fun open(k: ByteArray, d: ByteArray): ByteArray? = try {
        Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.DECRYPT_MODE, SecretKeySpec(k, "AES"), GCMParameterSpec(128, d, 0, 12))
            doFinal(d, 12, d.size - 12)
        }
    } catch (e: Exception) { null }
}

/*
 Protocolo (1º byte = tipo):
  H anfitrião -> participante : chave pública do anfitrião + nonce aleatório (16 bytes, novo a cada conexão)
  J participante -> anfitrião : chave pública + nome + prova de que sabe o código (HMAC com a chave do par, que inclui o nonce)
  K anfitrião -> participante : época (4 bytes) + chave do grupo, cifradas com a chave do par; época <= atual é descartada
  M mensagem : AES-256-GCM com a chave do grupo
  X anfitrião -> participante : recusado
 A chave do grupo é trocada a cada entrada/saída, então quem entra depois não lê o que veio antes.
*/
@Suppress("DEPRECATION")
@SuppressLint("MissingPermission")
class BleChat(
    private val ctx: Context,
    private val onMsg: (String) -> Unit,
    private val onStatus: (String) -> Unit
) {
    companion object {
        private const val MAX_MEMBERS = 8
        private const val MAX_OUT_QUEUE = 256
        private const val MAX_FRAME_BYTES = 244 // ATT payload after requesting MTU 247
        private const val MAX_SEEN_FRAMES = 2048
    }

    private val mgr = ctx.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
    private val adapter = mgr.adapter
    private val ui = Handler(Looper.getMainLooper())
    val me = newCode(4)
    private var server: BluetoothGattServer? = null
    private var gatt: BluetoothGatt? = null
    private var ch: BluetoothGattCharacteristic? = null
    private var advCb: AdvertiseCallback? = null
    private var scanCb: ScanCallback? = null
    private val outQ = ArrayDeque<Pair<BluetoothDevice?, ByteArray>>()
    private var busy = false
    private var seq = 0

    private data class PendingHandshake(val keyPair: KeyPair, val nonce: ByteArray)
    private val pendingHost = ConcurrentHashMap<BluetoothDevice, PendingHandshake>()
    private val connectedDevices = ConcurrentHashMap<BluetoothDevice, Boolean>()
    private val seenFrames = LinkedHashMap<String, Unit>(MAX_SEEN_FRAMES, 0.75f, true)
    private var code = ""
    @Volatile private var gk: ByteArray? = null
    private data class Member(val pairKey: ByteArray, val name: String, var lastMessageSeq: Long = -1)
    private data class JoinFailure(var count: Int = 0, var blockedUntil: Long = 0, var last: Long = 0)
    private val members = ConcurrentHashMap<BluetoothDevice, Member>()
    private val joinFailures = ConcurrentHashMap<BluetoothDevice, JoinFailure>()
    private val joinTimers = ConcurrentHashMap<BluetoothDevice, Runnable>()  // anfitrião: prazo para autenticar
    @Volatile private var epoch = 0                                       // época da chave do grupo
    @Volatile private var giveUp = false                                  // participante: busca encerrada
    private var pairK: ByteArray? = null                                  // participante
    private var clientMessageSeq = 0L
    private var hostMessageSeq = 0L
    private val lastReceivedSeq = ConcurrentHashMap<String, Long>()
    private val tried = mutableSetOf<String>()

    private fun msg(s: String) { ui.post { onMsg(s) } }
    private fun status(s: String) { ui.post { onStatus(s) } }
    private fun fit(s: String): ByteArray { var t = s; while (t.toByteArray().size > 180) t = t.dropLast(1); return t.toByteArray() }
    private fun frame(t: Char, b: ByteArray = ByteArray(0)) = byteArrayOf(t.code.toByte()) + b
    private fun body(f: ByteArray) = f.copyOfRange(1, f.size)
    // Discard delayed messages from an old membership epoch.
    private fun dec(f: ByteArray): ByteArray? = gk?.let { Crypto.open(it, body(f)) }

    @Synchronized private fun decNewMessage(f: ByteArray): ByteArray? {
        val plain = dec(f) ?: return null
        val id = MessageDigest.getInstance("SHA-256").digest(f).joinToString("") { "%02x".format(it) }
        if (seenFrames.containsKey(id)) return null
        seenFrames[id] = Unit
        if (seenFrames.size > MAX_SEEN_FRAMES) seenFrames.remove(seenFrames.entries.first().key)
        return plain
    }

    @Synchronized private fun installEpoch(ep: Int, key: ByteArray): Boolean {
        if (ep <= epoch) return false
        gk?.fill(0)
        epoch = ep
        gk = key
        seenFrames.clear()
        return true
    }

    @Synchronized private fun nextHostSequence(): Long = ++hostMessageSeq
    @Synchronized private fun nextClientSequence(): Long = ++clientMessageSeq

    @Synchronized private fun acceptHostMessage(plain: ByteArray): String? {
        val fields = String(plain, Charsets.UTF_8).split('|', limit = 3)
        if (fields.size != 3 || fields[0].any { it !in CHARS }) return null
        val seq = fields[1].toLongOrNull() ?: return null
        val previous = lastReceivedSeq[fields[0]] ?: -1L
        if (seq <= previous) return null
        lastReceivedSeq[fields[0]] = seq
        return "${fields[0]}|${fields[2]}"
    }

    @Synchronized private fun enqueue(d: BluetoothDevice?, b: ByteArray) {
        if (b.size > MAX_FRAME_BYTES || outQ.size >= MAX_OUT_QUEUE) {
            if (d != null) server?.cancelConnection(d) else gatt?.disconnect()
            status("Limite de envio atingido; conexão encerrada")
            return
        }
        outQ.add(d to b)
        pump()
    }
    @Synchronized private fun done() { busy = false; pump() }
    @Synchronized private fun dropQueued(d: BluetoothDevice) { outQ.removeIf { it.first == d } }
    // Se o callback de envio nunca vier, destrava a fila em vez de parar para todos.
    @Synchronized private fun watchdog(my: Int) { if (busy && seq == my) { busy = false; pump() } }
    @Synchronized private fun pump() {
        if (busy) return
        val (dev, data) = outQ.poll() ?: return
        busy = true
        val my = ++seq
        ui.postDelayed({ watchdog(my) }, 5000L)
        ch!!.value = data
        val ok = if (dev != null) server!!.notifyCharacteristicChanged(dev, ch!!, false)
        else { ch!!.writeType = BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT; gatt!!.writeCharacteristic(ch!!) }
        if (!ok) { busy = false; pump() }
    }

    private fun broadcast(f: ByteArray) { members.keys.forEach { enqueue(it, f) } }

    // Mesmo lock de newEpoch/installEpoch: gk não pode ser zerada (fill) entre ler a chave e cifrar.
    @Synchronized fun send(text: String) {
        val k = gk ?: return
        if (server != null) {
            val plain = "$me|${nextHostSequence()}|$text"
            msg("$me|$text")
            broadcast(frame('M', Crypto.seal(k, fit(plain))))
        } else {
            val plain = "$me|${nextClientSequence()}|$text"
            enqueue(null, frame('M', Crypto.seal(k, fit(plain))))
        }
    }

    // ---------- Criar conversa ----------
    fun host(c: String) {
        code = c
        gk = Crypto.rand(32)
        val chr = BluetoothGattCharacteristic(
            CHAR_UUID,
            BluetoothGattCharacteristic.PROPERTY_WRITE or BluetoothGattCharacteristic.PROPERTY_NOTIFY,
            BluetoothGattCharacteristic.PERMISSION_WRITE
        )
        chr.addDescriptor(BluetoothGattDescriptor(CCC, BluetoothGattDescriptor.PERMISSION_READ or BluetoothGattDescriptor.PERMISSION_WRITE))
        ch = chr
        server = mgr.openGattServer(ctx, object : BluetoothGattServerCallback() {
            override fun onConnectionStateChange(d: BluetoothDevice, s: Int, n: Int) {
                if (n == BluetoothProfile.STATE_CONNECTED) {
                    connectedDevices[d] = true
                    if (connectedDevices.size > MAX_MEMBERS) {
                        connectedDevices.remove(d)
                        server?.cancelConnection(d)
                        return
                    }
                    armJoinTimer(d)
                    return
                }
                if (n == BluetoothProfile.STATE_DISCONNECTED) {
                    connectedDevices.remove(d)
                    disarmJoinTimer(d)
                    pendingHost.remove(d)
                    // Sai da lista, limpa a fila e zera a chave no mesmo lock do rekey: nenhum K novo chega a quem saiu.
                    val removed = synchronized(this@BleChat) {
                        val m = members.remove(d)
                        dropQueued(d)
                        m?.also { it.pairKey.fill(0) }
                    }
                    if (removed != null) {
                        newEpoch() // quem saiu não recebe a nova chave
                        status("Participantes: ${members.size}")
                    }
                }
            }
            override fun onDescriptorWriteRequest(d: BluetoothDevice, id: Int, desc: BluetoothGattDescriptor, prep: Boolean, resp: Boolean, off: Int, v: ByteArray?) {
                val valid = desc.uuid == CCC && !prep && off == 0
                val enable = v?.contentEquals(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE) == true
                val disable = v?.contentEquals(BluetoothGattDescriptor.DISABLE_NOTIFICATION_VALUE) == true
                val result = when {
                    !valid -> BluetoothGatt.GATT_REQUEST_NOT_SUPPORTED
                    !enable && !disable -> BluetoothGatt.GATT_FAILURE
                    else -> BluetoothGatt.GATT_SUCCESS
                }
                if (resp) server?.sendResponse(d, id, result, 0, null)
                if (result != BluetoothGatt.GATT_SUCCESS) return
                if (disable) {
                    pendingHost.remove(d)
                    dropQueued(d)
                    return
                }
                if (pendingHost.containsKey(d) || members.containsKey(d)) return
                val kp = Crypto.newPair()
                val nonce = Crypto.rand(16)
                pendingHost[d] = PendingHandshake(kp, nonce)
                enqueue(d, frame('H', kp.public.encoded + nonce))
            }
            override fun onCharacteristicWriteRequest(d: BluetoothDevice, id: Int, c: BluetoothGattCharacteristic, prep: Boolean, resp: Boolean, off: Int, v: ByteArray?) {
                val valid = c.uuid == CHAR_UUID && !prep && off == 0 && v != null && v.isNotEmpty() && v.size <= MAX_FRAME_BYTES
                if (resp) server?.sendResponse(d, id, if (valid) BluetoothGatt.GATT_SUCCESS else BluetoothGatt.GATT_INVALID_ATTRIBUTE_LENGTH, 0, null)
                if (valid) hostFrame(d, v!!)
            }
            override fun onNotificationSent(d: BluetoothDevice, s: Int) { done() }
        })
        val svc = BluetoothGattService(APP_UUID, BluetoothGattService.SERVICE_TYPE_PRIMARY)
        svc.addCharacteristic(chr)
        server!!.addService(svc)
        advCb = object : AdvertiseCallback() {
            override fun onStartFailure(e: Int) { status("Falha ao anunciar ($e)") }
        }
        adapter.bluetoothLeAdvertiser?.startAdvertising(
            AdvertiseSettings.Builder().setConnectable(true).setTimeout(0)
                .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY).build(),
            AdvertiseData.Builder().setIncludeDeviceName(false).addServiceUuid(ParcelUuid(APP_UUID)).build(),
            advCb
        ) ?: status("Aparelho sem suporte a anúncio BLE")
    }

    @Synchronized private fun hostFrame(d: BluetoothDevice, v: ByteArray) {
        when (v[0].toInt().toChar()) {
            'J' -> hostJoin(d, v)
            'M' -> members[d]?.let { member ->
                decNewMessage(v)?.let { plain ->
                    // The host assigns the sender name from the connected BLE device.
                    val supplied = String(plain, Charsets.UTF_8)
                    val fields = supplied.split('|', limit = 3)
                    if (fields.size != 3) return@let
                    val seq = fields[1].toLongOrNull() ?: return@let
                    if (seq <= member.lastMessageSeq) return@let
                    member.lastMessageSeq = seq
                    val text = fields[2]
                    val stamped = frame('M', Crypto.seal(gk ?: return, fit("${member.name}|${nextHostSequence()}|$text")))
                    msg("${member.name}|$text")
                    broadcast(stamped)
                }
            }
        }
    }

    // Conexão que não autentica em 10 s é cortada (evita ocupar os slots GATT).
    private fun armJoinTimer(d: BluetoothDevice) {
        val r = Runnable { joinTimers.remove(d); if (!members.containsKey(d)) server?.cancelConnection(d) }
        joinTimers.put(d, r)?.let { ui.removeCallbacks(it) }
        ui.postDelayed(r, 10_000L)
    }
    private fun disarmJoinTimer(d: BluetoothDevice) { joinTimers.remove(d)?.let { ui.removeCallbacks(it) } }

    private fun pruneFailures(now: Long) {
        joinFailures.entries.removeIf { now - it.value.last > 300_000L && now >= it.value.blockedUntil }
        if (joinFailures.size > 256) joinFailures.clear()
    }

    @Synchronized private fun hostJoin(d: BluetoothDevice, v: ByteArray) {
        val now = SystemClock.elapsedRealtime()
        val pending = pendingHost.remove(d) ?: return reject(d) // um J por H: replay não tem nonce válido
        if (joinFailures[d]?.blockedUntil?.let { now < it } == true) return reject(d)
        if (v.size != 128) return reject(d)
        val pubJ = v.copyOfRange(1, 92)
        val nameBytes = v.copyOfRange(92, 96)
        val name = String(nameBytes, Charsets.US_ASCII)
        val proof = v.copyOfRange(96, 128)
        if (name.any { it !in CHARS }) return reject(d)
        val pubH = pending.keyPair.public.encoded
        val pk = try { Crypto.pairKey(pending.keyPair.private, Crypto.pub(pubJ), code, pubJ, pubH, pending.nonce) } catch (e: Exception) { return reject(d) }
        if (!MessageDigest.isEqual(Crypto.hmac(pk, "J".toByteArray(Charsets.US_ASCII), nameBytes), proof)) {
            pk.fill(0)
            if (joinFailures.size > 32) pruneFailures(now)
            val f = joinFailures.computeIfAbsent(d) { JoinFailure() }
            f.count++
            f.last = now
            if (f.count >= 5) {
                f.count = 0
                f.blockedUntil = now + 60_000L
                status("Muitas tentativas deste aparelho; aguarde 60 segundos")
            }
            return reject(d)
        }
        // Nome único: não pode repetir o do anfitrião nem o de outro participante.
        if (name == me || members.any { it.key != d && it.value.name == name }) return reject(d)
        if (members.size >= MAX_MEMBERS) return reject(d)
        joinFailures.remove(d)
        disarmJoinTimer(d)
        members[d] = Member(pk, name)
        newEpoch() // nova chave a cada entrada
        status("Participantes: ${members.size}")
    }

    @Synchronized private fun newEpoch() {
        gk?.fill(0)
        epoch++
        gk = Crypto.rand(32)
        seenFrames.clear()
        rekey()
    }
    private fun rekey() {
        val k = gk ?: return
        val payload = ByteBuffer.allocate(36).putInt(epoch).put(k).array()
        members.forEach { (d, member) -> enqueue(d, frame('K', Crypto.seal(member.pairKey, payload))) }
        payload.fill(0)
    }
    private fun reject(d: BluetoothDevice) { enqueue(d, frame('X')); ui.postDelayed({ server?.cancelConnection(d) }, 800) }

    // ---------- Entrar em conversa ----------
    fun join(c: String) {
        code = c
        status("Procurando conversa $c...")
        scanCb = object : ScanCallback() {
            override fun onScanResult(t: Int, r: ScanResult) {
                if (giveUp || gatt != null || !tried.add(r.device.address)) return
                status("Conectando...")
                val g = r.device.connectGatt(ctx, false, gattCb(), BluetoothDevice.TRANSPORT_LE)
                gatt = g
                // Anunciante falso ou lento: solta a conexão e a busca tenta outro aparelho.
                ui.postDelayed({ if (gk == null && gatt === g) g.disconnect() }, 10_000L)
            }
            override fun onScanFailed(e: Int) { status("Falha na busca ($e)") }
        }
        adapter.bluetoothLeScanner.startScan(
            listOf(ScanFilter.Builder().setServiceUuid(ParcelUuid(APP_UUID)).build()),
            ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY).build(), scanCb
        )
        ui.postDelayed({
            if (gk == null) {
                giveUp = true
                stopScan()
                gatt?.disconnect()
                status("Conversa não encontrada ou código incorreto")
            }
        }, 20000)
    }

    private fun gattCb() = object : BluetoothGattCallback() {
        override fun onConnectionStateChange(g: BluetoothGatt, st: Int, n: Int) {
            if (n == BluetoothProfile.STATE_CONNECTED) g.requestMtu(247)
            else {
                g.close()
                if (gk == null) { gatt = null; pairK = null; if (!giveUp) status("Procurando conversa $code...") } // tenta outro aparelho
                else status("Desconectado")
            }
        }
        override fun onMtuChanged(g: BluetoothGatt, mtu: Int, st: Int) { g.discoverServices() }
        override fun onServicesDiscovered(g: BluetoothGatt, st: Int) {
            val c = g.getService(APP_UUID)?.getCharacteristic(CHAR_UUID) ?: return g.disconnect()
            ch = c
            g.setCharacteristicNotification(c, true)
            val d = c.getDescriptor(CCC) ?: return g.disconnect() // anunciante falso sem o descritor não derruba o app
            d.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
            g.writeDescriptor(d)
        }
        override fun onDescriptorWrite(g: BluetoothGatt, d: BluetoothGattDescriptor, st: Int) { status("Trocando chaves...") }
        override fun onCharacteristicWrite(g: BluetoothGatt, c: BluetoothGattCharacteristic, st: Int) { done() }
        override fun onCharacteristicChanged(g: BluetoothGatt, c: BluetoothGattCharacteristic) {
            val v = c.value ?: return
            if (v.isEmpty()) return
            when (v[0].toInt().toChar()) {
                'H' -> {
                    if (pairK != null || v.size != 108) return // um H por conexão: 1 + 91 (chave) + 16 (nonce)
                    try {
                        val pubH = v.copyOfRange(1, 92)
                        val nonce = v.copyOfRange(92, 108)
                        val kp = Crypto.newPair()
                        val pubJ = kp.public.encoded
                        val pk = Crypto.pairKey(kp.private, Crypto.pub(pubH), code, pubJ, pubH, nonce)
                        pairK = pk
                        val nameBytes = me.toByteArray(Charsets.US_ASCII)
                        enqueue(null, frame('J', pubJ + nameBytes + Crypto.hmac(pk, "J".toByteArray(Charsets.US_ASCII), nameBytes)))
                    } catch (e: Exception) { g.disconnect() }
                }
                'K' -> {
                    val p = pairK?.let { Crypto.open(it, body(v)) } ?: return
                    if (p.size != 36) return
                    val ep = ByteBuffer.wrap(p, 0, 4).int
                    val first = gk == null
                    if (!installEpoch(ep, p.copyOfRange(4, 36))) { p.fill(0); return } // K antigo reenviado
                    p.fill(0)
                    if (first) { stopScan(); status("Conectado (criptografado)") }
                }
                'X' -> g.disconnect()
                'M' -> decNewMessage(v)?.let { acceptHostMessage(it)?.let(::msg) }
            }
        }
    }

    private fun stopScan() { scanCb?.let { adapter.bluetoothLeScanner?.stopScan(it) } }

    fun stop() {
        ui.removeCallbacksAndMessages(null)
        stopScan()
        advCb?.let { adapter.bluetoothLeAdvertiser?.stopAdvertising(it) }
        server?.close()
        gatt?.disconnect(); gatt?.close()
        // Zera as chaves no mesmo lock de quem as usa (send, hostFrame, newEpoch, installEpoch).
        synchronized(this) {
            pendingHost.clear(); connectedDevices.clear(); joinTimers.clear()
            members.values.forEach { it.pairKey.fill(0) }
            members.clear(); joinFailures.clear(); seenFrames.clear(); lastReceivedSeq.clear(); outQ.clear(); busy = false
            gk?.fill(0); gk = null
            pairK?.fill(0); pairK = null
        }
    }
}
