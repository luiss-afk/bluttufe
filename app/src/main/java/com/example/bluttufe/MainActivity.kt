package com.example.bluttufe // ajuste para o package do seu projeto

import android.Manifest
import android.annotation.SuppressLint
import android.bluetooth.*
import android.bluetooth.le.*
import android.content.Context
import android.content.pm.PackageManager
import android.os.*
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import java.security.SecureRandom
import java.util.ArrayDeque
import java.util.UUID

const val CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
val CHAR_UUID: UUID = UUID.fromString("5b1a7e02-0000-4000-8000-00805f9b34fb")
val CCC: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")
val PERMS = if (Build.VERSION.SDK_INT >= 31)
    arrayOf(Manifest.permission.BLUETOOTH_SCAN, Manifest.permission.BLUETOOTH_CONNECT, Manifest.permission.BLUETOOTH_ADVERTISE)
else arrayOf(Manifest.permission.ACCESS_FINE_LOCATION)

// 16 characters from a 32-symbol alphabet provide 80 bits of entropy,
// making offline guessing of the pairing proof impractical.
fun newCode(length: Int = 16): String = SecureRandom().let { r -> (1..length).map { CHARS[r.nextInt(CHARS.length)] }.joinToString("") }

class MainActivity : ComponentActivity() {
    override fun onCreate(b: Bundle?) {
        super.onCreate(b)
        setContent { MaterialTheme { Surface { App() } } }
    }
}

@Composable
fun App() {
    val ctx = LocalContext.current
    var screen by remember { mutableStateOf("home") } // home | join | chat
    var code by remember { mutableStateOf("") }
    var status by remember { mutableStateOf("") }
    var text by remember { mutableStateOf("") }
    val msgs = remember { mutableStateListOf<String>() }
    var chat by remember { mutableStateOf<BleChat?>(null) }
    var pending by remember { mutableStateOf<(() -> Unit)?>(null) }
    val askPerm = rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { r ->
        if (r.values.all { it }) pending?.invoke() else status = "Permissão negada"
    }

    fun go(act: () -> Unit) {
        val ad = (ctx.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager).adapter
        if (ad?.isEnabled != true) { status = "Ligue o Bluetooth"; return }
        if (PERMS.all { ContextCompat.checkSelfPermission(ctx, it) == PackageManager.PERMISSION_GRANTED }) act()
        else { pending = act; askPerm.launch(PERMS) }
    }

    fun iniciar(host: Boolean) = go {
        msgs.clear()
        status = if (host) "Aguardando participantes..." else ""
        if (host) code = newCode()
        val c = BleChat(ctx, { msgs.add(it) }, { status = it })
        chat = c; screen = "chat"
        if (host) c.host(code) else c.join(code)
    }

    Column(Modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        when (screen) {
            "home" -> {
                Spacer(Modifier.weight(1f))
                Text("Bluttufe", fontSize = 32.sp)
                Text("Conversa por Bluetooth, sem internet")
                Button({ iniciar(true) }, Modifier.fillMaxWidth()) { Text("Criar conversa") }
                Button({ code = ""; status = ""; screen = "join" }, Modifier.fillMaxWidth()) { Text("Entrar em uma conversa") }
                Text(status)
                Spacer(Modifier.weight(1f))
            }
            "join" -> {
                Text("Digite o código da conversa", fontSize = 22.sp)
                OutlinedTextField(code, { code = it.uppercase().filter { c -> c in CHARS }.take(16) }, Modifier.fillMaxWidth(), singleLine = true)
                Button({ iniciar(false) }, Modifier.fillMaxWidth(), enabled = code.length == 16) { Text("Entrar") }
                TextButton({ screen = "home" }) { Text("Voltar") }
                Text(status)
            }
            else -> {
                Text("Código: $code", fontSize = 28.sp)
                Text(status)
                LazyColumn(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    items(msgs) { m ->
                        val p = m.split("|", limit = 2)
                        val mine = p[0] == chat?.me
                        Row(Modifier.fillMaxWidth(), horizontalArrangement = if (mine) Arrangement.End else Arrangement.Start) {
                            Surface(
                                color = if (mine) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceVariant,
                                shape = MaterialTheme.shapes.medium
                            ) { Text(if (mine) p.getOrElse(1) { "" } else "${p[0]}: ${p.getOrElse(1) { "" }}", Modifier.padding(8.dp)) }
                        }
                    }
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    OutlinedTextField(text, { text = it.take(100) }, Modifier.weight(1f), singleLine = true)
                    Spacer(Modifier.width(8.dp))
                    Button({ if (text.isNotBlank()) { chat?.send(text.trim()); text = "" } }) { Text("Enviar") }
                }
                TextButton({ chat?.stop(); chat = null; status = ""; screen = "home" }) { Text("Sair") }
            }
        }
    }
}
