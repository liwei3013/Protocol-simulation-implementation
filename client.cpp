//This is Client
#include<iostream>
#include<ctime>
#include <WinSock2.h>

#pragma comment(lib, "ws2_32.lib")

//#include<string.h>

//using namespace std;



#define MR_PAIRING_SSP   
#define AES_SECURITY 80
#define SENDBUFFER 100
#define len64 64
#define len40 40
#define len20 20

#include "pairing_1.h"

//放在最前面保证能够先去其他结构拿到 mip 指针 不然其他结构化时
//这个mip为0 无法继续 进不了 main 

PFC pfc(AES_SECURITY);

/********************Struct Defines***************/
/*Client Registraion Phase  SD */

struct G1_Xor_Zq{
	Big x_xor;
	Big y_xor;
};

struct T_ui_xor{
	char servername[41];
	Big x_xor;
	Big y_xor;
	//加链表域
	T_ui_xor * next;
};

struct ClientParas{
	T_ui_xor * T_ui=NULL;
	G1_Xor_Zq G_ui;
	Big  V_ui;
	Big H_1_ASK;
	Big W_ui;
	Big h1;
	struct Time{
		GT B_ui;
		Big d_tui;
		Big t;
	}Time;
} gClientParas;


/********************End***************/

/*-------Function Declaration--------*/
void xor(Big & a, Big & b, Big &c);
void xor1(G1 & a, Big & b, G1_Xor_Zq & res);
void Store_T_ui(Big & PWD_ui, Big & PBIO_ui, G1 &d_ui,char* servername);
void Store_SD(G1_Xor_Zq & G_ui, Big & V_ui, Big& r_ui, char* finger, Big& PBIO_ui);
void Store_Time_Key(Big & PID_ui);
void H_00(char * name, G1 & HID_soru);
void H_01(Big & PID_ui, G1 & HID_soru);
Big H_1(Big &HAS);
Big H_2(char *name, Big &r_ui);
Big H_3(char* password, Big &PID_ui, Big &r_ui);
Big H_4(Big & PWD_ui, G1_Xor_Zq & G_ui);
Big H_5(GT B_ui, Big& PID_ui, Big& t);
Big H_6(GT &k_ui, char*servername, Big& H_1_ASK);
Big H_7(GT& k1, GT &k_sj, GT &k_ui, GT &g_pub, Big&PID_ui, char*servername);

void user_registration();
void testregis();

void test_pulic_params();

int login_and_exchanging();
int Exchanging(char * servername, Big & r_ui, Big &PBIO_ui,
	Big &PID_ui, Big & PWD_ui);

int change_password_finger();
void updata_new_server();
void memory_clear();
/*---------------End------------------*/

/*+++++++++++++++Global++++++++++++++++++*/
char *cs1 = "4B27AA7BC8BBC22583EF30FFAF0884240FE6590C";
char *cs2 = "7A724F4454587FD1F32948073972D3720A6CED02";
//char *pha = "12364564545664564ABABEEFFCC4354434567890";
Big s_1, s_2, HAS;
char phas[41] = "1234567890";
G1 P, P_pub;
GT g, g_pub;

/*+++++++++++++++++++++++++++++++++++++++++++++++++++*/

int main(){
	time_t seed;
	time(&seed);
	irand((long)seed);
	/*---------------Initailize system paramter------------*/
	//phase 1
	Big t_s_1(cs1);
	s_1 = t_s_1;

	Big t_s_2(cs2);
	s_2 = t_s_2;
	//共享不能随机pfc.random(HAS);
	Big task(phas);
	HAS = task;

	pfc.hash_and_map(P, (char*)"genetator");
	//phase 2
	P_pub = pfc.mult(P, s_1);
	g = pfc.pairing(P, P);
	g_pub = pfc.pairing(P, pfc.mult(P, s_2));

	test_pulic_params(); //看server和Client 参数是否相同
	/*-----------------------------------------------------*/
	while (1){
		int b = 0,fexit=1;
		if (fexit == 0)break;
		cout << "Enter 0 --> User Registration Phase" << endl;
		cout << "Enter 1 --> Login And Exchanging" << endl;
		cout << "Enter 2 --> Change New Password And Fingerprint" << endl;
		cout << "Enter 3 --> Updata New Server" << endl;
		cout << "Enter 4 --> Termination Process" << endl;
		cin >> b;
		switch (b){
			case 0:user_registration(); testregis(); break;
			case 1:{
				if (login_and_exchanging())
					cout << "Has been successful completed authentication and agreement key " << endl;
				else
					cout << "This authentication and agreement key failed" << endl;
				break;
			}
			case 2:{
				if (change_password_finger())
					cout << "Has been successful change password and fingerprint" << endl;
				else
					cout << "This change failed" << endl;
				break;
			}
			case 3:updata_new_server(); break;
			case 4:fexit=0; break;
			default:cout << "Wrong,try again" << endl;
		}
	}
	memory_clear();
}

/*-------Functions defines--------*/
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

int change_password_finger(){
	char password[41], finger[41], name[41];
	Big r_ui, PID_ui, PWD_ui, PBIO_ui, V_ui;
	cout << "Please enter your ID (< 40 characters)" << endl;
	cin >> name;
	cout << "Please enter your password (< 40 characters)" << endl;
	cin >> password;
	cout << "Please enter your fingerprint (< than 40 characters)" << endl;
	cin >> finger;
	pfc.random(r_ui);
	Big o_ui = pfc.hash_to_group(finger);
	
	
	xor(gClientParas.W_ui, H_1(o_ui), r_ui);
	
	PID_ui = H_2(name, r_ui);
	PWD_ui = H_3(password, PID_ui, r_ui);
	PBIO_ui = H_2(finger, r_ui);


	if (gClientParas.V_ui == H_4(PWD_ui, gClientParas.G_ui))
		cout << "Login successful" << endl;
	else{
		cout << "Login failed" << endl;
		return 0;
	}
	cout << "Please Enter New Password" << endl;
	cin >> password;
	cout << "Please Enter New Fingerprint" << endl;
	cin >> finger;
	//Update G_ui
	Big PWD_nui = H_3(password, PID_ui, r_ui);
	Big PBIO_nui = H_2(finger, r_ui);
	xor(gClientParas.G_ui.y_xor, PWD_ui, gClientParas.G_ui.y_xor);
	xor(gClientParas.G_ui.y_xor, PWD_nui, gClientParas.G_ui.y_xor);
	
	//Updata h1
	xor(gClientParas.h1, PBIO_ui, gClientParas.h1);
	xor(gClientParas.h1, PBIO_nui, gClientParas.h1);
	
	
	Big o_nui = pfc.hash_to_group(finger);
	
	//Updata W_ui
	xor(gClientParas.W_ui, H_1(o_ui), gClientParas.W_ui);
	xor(gClientParas.W_ui, H_1(o_nui), gClientParas.W_ui);

	//Updata V_ui
	gClientParas.V_ui = H_4(PWD_nui, gClientParas.G_ui);

	//Updata T_ui  不能改变全局的任何值 用临时变量
	T_ui_xor * tp_T_ui = gClientParas.T_ui;
	while (tp_T_ui){
		xor(tp_T_ui->x_xor, PWD_ui, tp_T_ui->x_xor);
		xor(tp_T_ui->x_xor, PWD_nui, tp_T_ui->x_xor);

		xor(tp_T_ui->y_xor, PBIO_ui, tp_T_ui->y_xor);
		xor(tp_T_ui->y_xor, PBIO_nui, tp_T_ui->y_xor);

		tp_T_ui = tp_T_ui->next;
	}
}

void updata_new_server(){
	char servername[41];
	cout << "Make sure the updated server is already registered" << endl;
	cout << "Enter new Server name ( <40 characters )" << endl;
	cin >> servername;
	char password[41], finger[41], name[41];
	Big r_ui, PID_ui, PWD_ui, PBIO_ui;
	cout << "Please enter your ID (< 40 characters)" << endl;
	cin >> name;
	cout << "Please enter your password (< 40 characters)" << endl;
	cin >> password;
	cout << "Please enter your fingerprint (< than 40 characters)" << endl;
	cin >> finger;
	pfc.random(r_ui);
	Big o_ui = pfc.hash_to_group(finger);
	xor(gClientParas.W_ui, H_1(o_ui), r_ui);

	PID_ui = H_2(name, r_ui);
	PWD_ui = H_3(password, PID_ui, r_ui);
	
	PBIO_ui = H_2(finger, r_ui);

	//Restore d_ui
	printf("Restore d_ui\n");
	//No chagne global value
	Big t_d_ui_x, t_d_ui_y;
	//In G1 Initialization Big random number
	t_d_ui_x = gClientParas.G_ui.x_xor;
	
	t_d_ui_y = gClientParas.G_ui.y_xor;
	
	xor(PWD_ui, gClientParas.G_ui.y_xor, t_d_ui_y);
	
	//cout<<t_d_ui_x<<endl;
	//cout<<t_d_ui_y<<endl;
	
	ECn e_d_ui;
	e_d_ui.set(t_d_ui_x,t_d_ui_y);
	
	//ECn e_d_ui(t_d_ui_x, t_d_ui_y);
	cout << e_d_ui << endl;
	//printf("Restore d_ui\n");
	G1 d_ui(e_d_ui);
	Store_T_ui(PWD_ui, PBIO_ui, d_ui, servername);
}

void  memory_clear(){
	T_ui_xor * tt = gClientParas.T_ui;
	while (tt){
		T_ui_xor * dt = tt->next;
		delete tt;
		tt = dt;
	}
	gClientParas.T_ui = NULL;
}

void user_registration(){
	char password[41], finger[41], name[41];
	Big r_ui, PID_ui, PWD_ui, PBIO_ui, V_ui;
	G1 HID_ui, d_ui, HID_sj;
	G1_Xor_Zq G_ui;
	cout << "Please enter your ID (< 40 characters)" << endl;
	cin >> name;
	cout << "Please enter your password (< 40 characters)" << endl;
	cin >> password;
	cout << "Please enter your fingerprint (< than 40 characters)" << endl;
	cin >> finger;
	/*We simplify fuzzy biological extraction
	and directly use input fingerprint as a token*/
	//phase 1 
	pfc.random(r_ui);

	printf("Create r_ui\n");
	cout << r_ui << endl;

	PID_ui = H_2(name, r_ui);
	PWD_ui = H_3(password, PID_ui, r_ui);
	PBIO_ui = H_2(finger, r_ui);
	//phase 2
	H_01(PID_ui, HID_ui);
	d_ui = pfc.mult(HID_ui, s_1);
	printf("Crate d_ui\n");
	cout<<d_ui.g<<endl;
	xor1(d_ui, PWD_ui, G_ui);
	V_ui = H_4(PWD_ui, G_ui);
	//先默认注册"BobServer" 的服务
	Store_T_ui(PWD_ui, PBIO_ui, d_ui, (char*)"BobServer");
	Store_SD(G_ui, V_ui, r_ui, finger, PBIO_ui);
	//跟新时间密钥 
	Store_Time_Key(PID_ui);
}

//wacth out wheather over =汉语注释第一行不显示 奔溃 注意赋值运算
void testregis(){
	printf("Print the contents of the SD card\n");

	printf("T_ui\n");
	cout << gClientParas.T_ui->servername << endl;
	cout << gClientParas.T_ui->x_xor << endl;
	cout << gClientParas.T_ui->y_xor << endl;

	printf("G_ui\n");
	cout << gClientParas.G_ui.x_xor << endl;
	cout << gClientParas.G_ui.y_xor << endl;

	printf("V_ui\n");
	cout << gClientParas.V_ui << endl;

	//printf("H_1_ASK\n");
	//cout << gClientParas.H_1_ASK << endl;

	printf("W_ui\n");
	cout << gClientParas.W_ui << endl;

	printf("h1\n");
	cout << gClientParas.h1 << endl;

	printf("Time\n");
	cout << gClientParas.Time.B_ui.g << endl;
	cout << gClientParas.Time.d_tui << endl;
	cout << gClientParas.Time.t << endl;
	printf(" END SD \n");
}

int login_and_exchanging(){
	char password[41], finger[41], name[41], servername[41];
	Big r_ui, PID_ui, PWD_ui, PBIO_ui, V_ui;
	cout << "Please enter your ID (< 40 characters)" << endl;
	cin >> name;
	cout << "Please enter your password (< 40 characters)" << endl;
	cin >> password;
	cout << "Please enter your fingerprint (< than 40 characters)" << endl;
	cin >> finger;
	pfc.random(r_ui);
	Big o_ui = pfc.hash_to_group(finger);
	xor(gClientParas.W_ui, H_1(o_ui), r_ui);

	printf("Restore r_ui\n");
	cout << r_ui << endl;

	PID_ui = H_2(name, r_ui);
	PWD_ui = H_3(password, PID_ui, r_ui);
	PBIO_ui = H_2(finger, r_ui);

	if (gClientParas.V_ui == H_4(PWD_ui, gClientParas.G_ui))
		cout << "Login successful" << endl;
	else{
		cout << "Login failed" << endl;
		return 0;
	}

	cout << "Please Server name (First time input:BobServer)" << endl;
	cin >> servername;
	if (Exchanging(servername, r_ui, PBIO_ui, PID_ui, PWD_ui)){
		cout << "Successful" << endl;
		return 1;
	}
	else{
		cout << "Wrong" << endl;
		return 0;
	}

};

int Exchanging(char * servername, Big & r_ui, Big &PBIO_ui,
	Big &PID_ui, Big & PWD_ui){
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);
	SOCKADDR_IN addrSrv;
	addrSrv.sin_family = AF_INET;
	addrSrv.sin_port = htons(8000);
	addrSrv.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
	SOCKET sockClient = socket(AF_INET, SOCK_STREAM, 0);
	connect(sockClient, (struct sockaddr *) &addrSrv, sizeof(addrSrv));
	Big N_1, H_1_ASK, F_ui;
	GT k_ui;
	pfc.random(N_1);
	H_1_ASK = N_1;

	printf("Test Big=Big overwrite\n");
	cout << H_1_ASK << endl;

	xor(gClientParas.h1, r_ui, H_1_ASK);
	xor(H_1_ASK, PBIO_ui, H_1_ASK);

	printf("Restore H_1_ASK\n");
	cout << H_1_ASK << endl;

	k_ui = pfc.power(g, N_1);
	F_ui = N_1;
	xor(PID_ui, H_6(k_ui, servername, H_1_ASK), F_ui);

	printf("Send F_ui\n");
	cout << F_ui << endl;
	char tempbuffer[SENDBUFFER];

	to_binary(F_ui, SENDBUFFER, tempbuffer);
	int res = send(sockClient, tempbuffer, SENDBUFFER, 0);

	printf("Send k_ui\n");
	cout << k_ui.g << endl;
	Big send_x, send_y;
	k_ui.g.get(send_x, send_y);
	to_binary(send_x, SENDBUFFER, tempbuffer);
	send(sockClient, tempbuffer, SENDBUFFER, 0);
	to_binary(send_y, SENDBUFFER, tempbuffer);
	send(sockClient, tempbuffer, SENDBUFFER, 0);

	printf("Send B_ui\n");
	cout << gClientParas.Time.B_ui.g << endl;
	gClientParas.Time.B_ui.g.get(send_x, send_y);
	to_binary(send_x, SENDBUFFER, tempbuffer);
	send(sockClient, tempbuffer, SENDBUFFER, 0);
	to_binary(send_y, SENDBUFFER, tempbuffer);
	send(sockClient, tempbuffer, SENDBUFFER, 0);

	printf("Send d_tui\n");
	cout << gClientParas.Time.d_tui << endl;
	to_binary(gClientParas.Time.d_tui, SENDBUFFER, tempbuffer);
	send(sockClient, tempbuffer, SENDBUFFER, 0);

	printf("Send t\n");
	cout << gClientParas.Time.t << endl;
	to_binary(gClientParas.Time.t, SENDBUFFER, tempbuffer);
	send(sockClient, tempbuffer, SENDBUFFER, 0);

	printf("Restore D_sj\n");
	recv(sockClient, tempbuffer, SENDBUFFER, 0);
	Big D_sj = from_binary(len20, tempbuffer);
	cout << D_sj << endl;

	printf("Restore k_sj\n");
	recv(sockClient, tempbuffer, SENDBUFFER, 0);
	Big rev_x = from_binary(len64, tempbuffer);

	recv(sockClient, tempbuffer, SENDBUFFER, 0);
	Big rev_y = from_binary(len64, tempbuffer);

	ZZn2 k_sj_g(rev_x, rev_y);
	GT k_sj(k_sj_g);
	cout << k_sj.g << endl;

	printf("The phase 2\n");
	printf("Restore k_1\n");
	T_ui_xor *p_temp = gClientParas.T_ui;
	while (p_temp){
		if (p_temp == NULL){
			cout << "Wrong server name or No " << endl;
			return 0;
		}
		if (0 == strcmp(p_temp->servername, servername))
			break;
		p_temp = p_temp->next;
	}
	Big  k_1_x, k_1_y;
	big t = p_temp->x_xor.getbig();
	k_1_x = t;
	k_1_y = t;
	//xor(p_temp->x_xor, PWD_ui, p_temp->x_xor); this way
	//destroy oringial data
	xor(p_temp->x_xor, PWD_ui, k_1_x);
	xor(p_temp->y_xor, PBIO_ui, k_1_y);
	ZZn2 k_1_g(k_1_x, k_1_y);
	GT k_1(k_1_g);
	cout << k_1.g << endl;
	if (D_sj != H_7(k_1, k_sj, k_ui, g_pub, PID_ui, servername))
		return 0;
	printf("Authentication Server side\n");
	GT k_u = pfc.power(k_sj, N_1);
	Big sk = H_7(k_u, g_pub, k_sj, k_ui, PID_ui, servername);
	printf("the key is: ");
	cout << sk << endl;

	printf("Send D_ui\n");
	Big D_ui = H_7(g_pub, k_ui, k_sj, k_1, PID_ui, servername);
	cout << D_ui << endl;
	to_binary(D_ui, SENDBUFFER, tempbuffer);
	send(sockClient, tempbuffer, SENDBUFFER, 0);

	closesocket(sockClient);
	WSACleanup();
	return 1;
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

void xor1(G1 & a, Big & b, G1_Xor_Zq & res){
	
	a.g.getxy(res.x_xor, res.y_xor);
	
	xor(b, res.y_xor, res.y_xor);
	
}

void Store_T_ui(Big & PWD_ui, Big & PBIO_ui, G1 &d_ui,char* servername){
	Big x, y;
	big t;
	G1 HID_sj;
	T_ui_xor* R_sj = new T_ui_xor;
	H_00(servername, HID_sj);
	GT Sertoken = pfc.pairing(d_ui, HID_sj);
	strcpy(R_sj->servername, servername);
	Sertoken.g.get(x, y);
	//pfc.random();只能初始化一个比较短的随机数 不满足要求
	t = x.getbig();
	R_sj->x_xor = t;
	R_sj->y_xor = t;
	R_sj->next = NULL;
	xor(x, PWD_ui, R_sj->x_xor);
	xor(y, PBIO_ui, R_sj->y_xor);//注意	Big初始化 才能异或

	T_ui_xor* temp = gClientParas.T_ui;
	gClientParas.T_ui = R_sj;
	R_sj->next = temp;
}

void Store_SD(G1_Xor_Zq & G_ui, Big & V_ui, Big& r_ui, char* finger, Big& PBIO_ui){
	Big o_ui = pfc.hash_to_group(finger);
	Big t = H_1(HAS);

	printf("Create H_1_ASK\n");
	cout << t << endl;

	Big W_ui, temp;
	pfc.random(W_ui);
	pfc.random(temp);
	xor(r_ui, H_1(o_ui), W_ui);
	xor(t, r_ui, temp);
	xor(temp, PBIO_ui, temp);
	gClientParas.W_ui = W_ui;
	gClientParas.G_ui = G_ui;//GT 重写了赋值操作所以OK 但是这里为啥OK呢
	gClientParas.V_ui = V_ui;
	//big bb=temp.getbig();
	gClientParas.h1 = temp;
	//gClientParas.h1 = temp.getbig();
}

void Store_Time_Key(Big & PID_ui){
	Big b_ui, d_tui, t;
	GT B_ui;
	pfc.random(b_ui);
	pfc.random(t);
	B_ui = pfc.power(g, b_ui);
	d_tui = b_ui + H_5(B_ui, PID_ui, t)*s_2;
	gClientParas.Time.B_ui = B_ui;
	gClientParas.Time.d_tui = d_tui;
	gClientParas.Time.t = t;
	//test
	if (pfc.power(g, d_tui) == B_ui*pfc.power(g_pub, H_5(B_ui, PID_ui, t)))
		cout << "Time Key Fine" << endl;
	else
		cout << "Wrong" << endl;
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
Big H_2(char *name, Big &r_ui){
	Big ID_ui = pfc.hash_to_group(name);
	//bytes_to_big(strlen(name), name, ID_ui);
	pfc.start_hash();
	pfc.add_to_hash(ID_ui);
	pfc.add_to_hash(r_ui);
	return  pfc.finish_hash_to_group();
}
Big H_3(char* password, Big &PID_ui, Big &r_ui){
	Big PW_ui = pfc.hash_to_group(password);
	//bytes_to_big(strlen(password), password, PW_ui);
	pfc.start_hash();
	pfc.add_to_hash(PW_ui);
	pfc.add_to_hash(PID_ui);
	pfc.add_to_hash(r_ui);
	return pfc.finish_hash_to_group();
}

Big H_4(Big & PWD_ui, G1_Xor_Zq & G_ui){
	pfc.start_hash();
	pfc.add_to_hash(PWD_ui);
	pfc.add_to_hash(G_ui.x_xor);
	pfc.add_to_hash(G_ui.y_xor);
	return  pfc.finish_hash_to_group();
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


/*-------------END---------------*/