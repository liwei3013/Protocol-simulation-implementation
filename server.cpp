//This is Server
#include<iostream>
#include<ctime>
#include <WinSock2.h>

#pragma comment(lib, "ws2_32.lib")


#define MR_PAIRING_SSP   
#define AES_SECURITY 80
#define SENDBUFFER 100
#define len64 64
#define len40 40
#define len20 20


#include "pairing_1.h"

PFC pfc(AES_SECURITY);

/*-----------------Struct Defines--------------------*/

struct ServerParas{
	ServerParas * next;
	char D_sj[40];
	G1 d_sj;
	Big H_1_ASK;
} *gServerParas;

/*----------------------END-------------------------*/

/*-------Functions defines--------*/
void xor(Big & a, Big & b, Big &c);
void H_00(char * name, G1 & HID_soru);
void H_01(Big & PID_ui, G1 & HID_soru);
Big H_1(Big &HAS);
Big H_5(GT B_ui, Big& PID_ui, Big& t);
Big H_6(GT &k_ui, char*servername, Big& H_1_ASK);
Big H_7(GT& k1, GT &k_sj, GT &k_ui, GT &g_pub, Big&PID_ui, char*servername);

void test_pulic_params();
int socket_comm();
void create_new_server();
void memory_clear();

/*-------------END---------------*/

/*+++++++++++++++Global++++++++++++++++++*/
//This public paramters
char *cs1 = "4B27AA7BC8BBC22583EF30FFAF0884240FE6590C";
char *cs2 = "7A724F4454587FD1F32948073972D3720A6CED02";
Big s_1, s_2, HAS;
char phas[41] = "1234567890";
G1 P, P_pub;
GT g_pub, g;
/*+++++++++++++++++++++++++++++++++++++++++++++*/

int main(){

	time_t seed;
	time(&seed);
	irand((long)seed);

	/*Initailize system paramter*/
	//phase 1
	Big t_s_1(cs1);
	s_1 = t_s_1;
	Big t_s_2(cs2);
	s_2 = t_s_2;
	Big task(phas);
	HAS = task;
	pfc.hash_and_map(P, (char*)"genetator");
	//phase 2
	P_pub = pfc.mult(P, s_1);
	g = pfc.pairing(P, P);
	g_pub = pfc.pairing(P, pfc.mult(P, s_2));
	//Check if pulic params are the same 
	test_pulic_params();
	//Initialize a default server: BobServer
	/*Server Registraion Phase*/
	//phase 2
	gServerParas = new ServerParas;
	gServerParas->next = NULL;
	G1 H_ID_sj;
	H_00((char*)"BobServer", H_ID_sj);
	gServerParas->d_sj = pfc.mult(H_ID_sj, s_1);
	gServerParas->H_1_ASK = H_1(HAS);
	strcpy(gServerParas->D_sj, (char*)"BobServer");


	//Choose an activity to perform
	while (1){
		int choose;
		cout << "Enter 1 --> Authentication and Key Agreement" << endl;
		cout << "Enter 2 -->Create a New Server" << endl;
		cout << "Enter 3 --> Termination Process" << endl;
		cin >> choose;
		if (choose == 1){ 
			if (socket_comm()) cout << "Has been successful completed authentication and agreement key"<<endl; 
			else cout << "This authentication and agreement key failed" << endl;
		}
		else if (choose == 2) {create_new_server();}
		else if (choose == 3) break;
		else cout << "Wrong number, try again" << endl;
	}
	memory_clear();
	
}

void create_new_server(){
	ServerParas *tpserverparas= new ServerParas;
	char servername[len40+1];
	cout << "Input new server name ( <40 characters)" << endl;
	cin >> servername;
	G1 H_ID_sj;
	H_00(servername, H_ID_sj);
	tpserverparas->d_sj = pfc.mult(H_ID_sj, s_1);
	tpserverparas->H_1_ASK = H_1(HAS);
	strcpy(tpserverparas->D_sj, servername);
	ServerParas *temp = gServerParas;
	gServerParas = tpserverparas;
	tpserverparas->next = temp;
}

void memory_clear(){
	ServerParas * tt = gServerParas;
	while (tt){
		ServerParas * dt = tt->next;
		delete tt;
		tt = dt;
	}
	gServerParas = NULL;
}

int socket_comm(){
	char servername[41];
	printf("Enter a name for the server to use for authentication.\n");
	printf("If you are not registered new server, please enter: BobServer .\n");
	printf ("Otherwise enter name of the server you registered\n");
	cin >> servername;
	//Look anthentication server
	ServerParas * gServer = gServerParas;
	int iflook = 0;
	while (gServer){
		if (strcmp(gServer->D_sj, servername)==0){ iflook = 1; break; }
		gServer = gServer->next;
	}
	if (iflook == 0){ cout << "No Such Server" << endl; return 0; }
	WSADATA wsadata;
	int iResult, port = 8000;
	char tempbuff[SENDBUFFER];
	printf("Server side has been initialized. Waiting for connection\n");
	iResult = WSAStartup(MAKEWORD(2, 2), &wsadata);
	if (iResult != NO_ERROR){
		printf("WSAStartup failed: %d\n", iResult);
	}
	SOCKET sockSrv = socket(AF_INET, SOCK_STREAM, 0);
	if (sockSrv == INVALID_SOCKET){
		printf("Error at socket(): %ld", WSAGetLastError());
		WSACleanup();
	}
	SOCKADDR_IN addrSrv;
	addrSrv.sin_family = AF_INET;
	addrSrv.sin_port = htons(port);
	addrSrv.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
	//addrSrv.sin_addr.S_un.S_addr = htonl(INADDR_ANY);
	iResult = bind(sockSrv, (LPSOCKADDR)& addrSrv, sizeof(SOCKADDR_IN));
	if (iResult == SOCKET_ERROR){
		wprintf(L"bind failed with error %u\n", WSAGetLastError());
		closesocket(sockSrv);
		WSACleanup();
	}
	if (listen(sockSrv, 10) == SOCKET_ERROR){
		wprintf(L"listen function failed with error: %d\n", WSAGetLastError());
	}
	SOCKADDR_IN addrClient;
	int len = sizeof(SOCKADDR);
	SOCKET sockConn = accept(sockSrv, (SOCKADDR *)& addrClient, &len);
	
	printf("The client side IP :%s\n", inet_ntoa(addrClient.sin_addr));

	printf("Restore F_ui\n");
	int res = recv(sockConn, tempbuff, SENDBUFFER, 0);
	Big F_ui = from_binary(len20, tempbuff);
	cout << F_ui << endl;

	printf("Restore k_ui\n");
	Big k_ui_x, k_ui_y;
	recv(sockConn, tempbuff, SENDBUFFER, 0);
	k_ui_x = from_binary(len64, tempbuff);
	//revc 第三个参数 取得大小 不会被00截断
	//send 发生数据大小 不会被00截断
	recv(sockConn, tempbuff, SENDBUFFER, 0);
	k_ui_y = from_binary(len64, tempbuff);
	ZZn2 k_ui_g(k_ui_x, k_ui_y);
	GT k_ui(k_ui_g);
	cout << k_ui.g << endl;

	printf("Restore B_ui\n");
	Big B_ui_x, B_ui_y;
	recv(sockConn, tempbuff, SENDBUFFER, 0);
	B_ui_x = from_binary(len64, tempbuff);
	recv(sockConn, tempbuff, SENDBUFFER, 0);
	B_ui_y = from_binary(len64, tempbuff);
	ZZn2 B_ui_g(B_ui_x, B_ui_y);
	GT B_ui(B_ui_g);
	cout << B_ui.g << endl;

	printf("Restord d_dui\n");
	recv(sockConn, tempbuff, SENDBUFFER, 0);
	Big d_tui = from_binary(len40, tempbuff);
	cout << d_tui << endl;

	printf("Restord t\n");
	recv(sockConn, tempbuff, SENDBUFFER, 0);
	Big t = from_binary(len20, tempbuff);
	cout << t << endl;

	//server compute phase1;
	Big PID_ui;
	pfc.random(PID_ui);
	xor(F_ui, H_6(k_ui, gServer->D_sj, gServer->H_1_ASK), PID_ui);

	cout << "Verification time key" << endl;
	if (pfc.power(g, d_tui) != B_ui*pfc.power(g_pub, H_5(B_ui, PID_ui, t))){
		cout << "Time key Wrong" << endl;
		return 0;
	}
	printf("Compute k_1t \n");
	G1 H_G1_PID_ui;
	H_01(PID_ui, H_G1_PID_ui);
	GT k_1t = pfc.pairing(gServer->d_sj, H_G1_PID_ui);
	Big N_2;
	pfc.random(N_2);
	GT k_sj = pfc.power(g, N_2);
	Big D_sj = H_7(k_1t, k_sj, k_ui, g_pub, PID_ui, gServer->D_sj);

	printf("Send D_sj\n");
	cout << D_sj << endl;
	to_binary(D_sj, SENDBUFFER, tempbuff);
	send(sockConn, tempbuff, SENDBUFFER, 0);

	printf("Send k_sj\n");
	cout << k_sj.g << endl;
	Big k_sj_x, k_sj_y;
	k_sj.g.get(k_sj_x, k_sj_y);
	to_binary(k_sj_x, SENDBUFFER, tempbuff);
	send(sockConn, tempbuff, SENDBUFFER, 0);
	to_binary(k_sj_y, SENDBUFFER, tempbuff);
	send(sockConn, tempbuff, SENDBUFFER, 0);

	printf("Restore D_ui\n");
	recv(sockConn, tempbuff, SENDBUFFER, 0);
	Big D_ui = from_binary(len20, tempbuff);
	cout << D_ui << endl;

	//Server compute phase 2
	cout << "Anthenticaton Client" << endl;
	if (D_ui != H_7(g_pub, k_ui, k_sj, k_1t, PID_ui, gServer->D_sj)){
		cout << "Anthentication Client Wrong" << endl;
		return 0;
	}
	GT k_s = pfc.power(k_ui, N_2);
	Big sk = H_7(k_s, g_pub, k_sj, k_ui, PID_ui, gServer->D_sj);
	printf("the key is: ");
	cout << sk << endl;
	closesocket(sockConn);
	closesocket(sockSrv);
	WSACleanup();

	return 1;
}

void test_pulic_params(){
	cout << "Verifty Pulib Params" << endl;
	cout << g.g << endl;
	cout << g_pub.g << endl;
	cout << P.g << endl;
	cout << P_pub.g << endl;
	cout << HAS << endl;
	cout << s_1 << endl;
	cout << s_2 << endl;
	cout << "Verifty Pulib Params End" << endl;
}

void xor(Big & a, Big & b, Big &c){
	int lena = strlen((char*)(a.getbig())->w);
	int lenb = strlen((char*)(b.getbig())->w);
	char *aw = (char*)(a.getbig())->w;
	char *bw = (char*)(b.getbig())->w;
	char *cw = (char*)(c.getbig())->w;
	if (lena<lenb) lena = lenb;
	for (int i = 0; i<lena; i++){
		cw[i] = (char)((unsigned short)aw[i] ^ (unsigned short)bw[i]);
	}
}

void H_00(char * name, G1 & HID_soru){
	pfc.hash_and_map(HID_soru, name);
}

void H_01(Big & PID_ui, G1 & HID_soru){
	pfc.hash_and_map(HID_soru, (char*)(PID_ui.getbig())->w);
}

Big H_1(Big &HAS){
	pfc.start_hash();
	pfc.add_to_hash(HAS);
	return pfc.finish_hash_to_group();
}

Big H_5(GT B_ui, Big& PID_ui, Big& t){
	pfc.start_hash();
	pfc.add_to_hash(B_ui);
	pfc.add_to_hash(PID_ui);
	pfc.add_to_hash(t);
	return  pfc.finish_hash_to_group();
}
Big H_6(GT &k_ui, char*servername, Big& H_1_ASK){
	Big t = pfc.hash_to_group(servername);
	pfc.start_hash();
	pfc.add_to_hash(k_ui);
	pfc.add_to_hash(t);
	pfc.add_to_hash(H_1_ASK);
	return pfc.finish_hash_to_group();
}
Big H_7(GT& k1, GT &k_sj, GT &k_ui, GT &g_pub, Big&PID_ui, char*servername){
	Big t = pfc.hash_to_group(servername);
	pfc.start_hash();
	pfc.add_to_hash(k1);
	pfc.add_to_hash(k_sj);
	pfc.add_to_hash(k_ui);
	pfc.add_to_hash(g_pub);
	pfc.add_to_hash(PID_ui);
	pfc.add_to_hash(t);
	return pfc.finish_hash_to_group();
}