var networkmanager = require('index.js');
var util = require('util');
var nPackages = 0;

var pcap = require('pcap'),
	tcp_tracker = new pcap.TCPTracker(),
	pcap_session = pcap.createSession('wlp3s0', 'ip proto \\tcp');
 
tcp_tracker.on('session', function (session) {
	console.log('Início de sessão entre ' + session.src_name + ' e ' + session.dst_name);
	
	session.on('end', function (session) {
		console.log('Fim da sessão TCP entre ' + session.src_name + ' e ' + session.dst_name);
		console.log('');
	});
});
 
pcap_session.on('packet', function(raw_packet) {
	var packet = pcap.decode.packet(raw_packet);
	tcp_tracker.track_packet(packet);
	var flags = packet.payload.payload.payload.flags;
	var header = packet.payload.payload.payload;

	console.log('-------------------------------------------------------------- Início do pacote --------------------------------------------------------------');
	console.log('Pacote número: ' + nPackages);
	console.log('Tipo de encapsulamento: ' + packet.link_type);
	console.log('Comprimento de frame: ' + packet.pcap_header.caplen + ' bytes');
	console.log('Comprimento de captura: ' + packet.pcap_header.len + ' bytes');
	console.log('Fonte: ' + ip2mac(packet.payload.shost.addr));
	console.log('Destino: ' + ip2mac(packet.payload.dhost.addr));
	console.log('Versão Internet Protocol: ' + packet.payload.payload.version);
	console.log('Tamanho do cabeçalho: ' + packet.payload.payload.headerLength);
	console.log('TTl: ' + packet.payload.payload.ttl);
	console.log('Checksum do cabeçalho: ' + packet.payload.payload.headerChecksum);
	console.log('Endereço da fonte: ' + packet.payload.payload.saddr.addr.join('.'));
	console.log('Endereço de destino: ' + packet.payload.payload.daddr.addr.join('.'));
	console.log('---------------------------------------------------------- Informações do cabeçalho ----------------------------------------------------------')
	console.log('Número porta origem: ' + header.sport);
	console.log('Número porta origem: ' + header.dport);
	console.log('Número de sequência: ' + header.seqno);
	console.log('Número de confirmação: ' + header.ackno);
	console.log('Comprimento do cabeçalho: ' + header.headerLength + ' bytes');
	console.log('Flags: [Nonce=' + flags.nonce + ' | CWR=' + flags.cwr + ' | ECN-Echo=' + flags.ece + ' | Urgent=' + flags.urg + ' | Acknowledgement=' + flags.ack + ' | Push=' + flags.psh + ' | Reset=' + flags.rst + ' | Syn=' + flags.syn + ' | Fin=' + flags.fin + ']');
	console.log('Tamanho da janela: ' + header.windowSize);
	console.log('Checksum: ' + header.checksum);
	console.log('Ponteiro de urgente: ' + header.urgentPointer);
	
	if (header.data != null) {
		console.log('------------------------------------------------------------------- Dados --------------------------------------------------------------------')
		console.log(header.data);
	}

	console.log('--------------------------------------------------------------- Fim do pacote ----------------------------------------------------------------');
	console.log('');
	console.log('');

	nPackages++;
});

function ip2mac(aIp) {
	var ip = [];

	for (var i = 0; i < aIp.length; i++) {
		ip.push((aIp[i]).toString(16));
	}

	return ip.join(':');
}