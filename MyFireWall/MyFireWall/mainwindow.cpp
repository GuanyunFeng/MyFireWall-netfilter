#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "MyfwApi.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    setWindowTitle("MyFireWall-gui");
    ui->reject_radioButton->setChecked(true);
    InitRuleTable();
    InitNatTable();
    InitStatuTable();
    InitLogTable();
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_add_pushButton_clicked()
{
    int row = ui->tableWidget_rule->rowCount();
    ui->tableWidget_rule->insertRow(row);
}

void MainWindow::on_apply_pushButton_clicked()
{
    short src_port, dst_port;
    char protocol;
    bool action, log;
    rnum = 0;
    int row = ui->tableWidget_rule->rowCount();
    for(int i = 0; i < row; i++){
        src_port = ui->tableWidget_rule->item(i, 2)->text().toShort();
        dst_port = ui->tableWidget_rule->item(i, 3)->text().toShort();
        protocol = ui->tableWidget_rule->item(i, 4)->text().toInt();
        action = ui->tableWidget_rule->item(i, 5)->text().toInt();
        log = ui->tableWidget_rule->item(i, 6)->text().toInt();
        AddRule(ui->tableWidget_rule->item(i, 0)->text().toLatin1().data(),
                ui->tableWidget_rule->item(i, 1)->text().toLatin1().data(),
                src_port, dst_port, protocol, action, log);
    }
    SendRules();
}

void MainWindow::on_del_pushButton_clicked()
{
    int rowIndex = ui->tableWidget_rule->currentRow();
    if (rowIndex != -1)
        ui->tableWidget_rule->removeRow(rowIndex);
}


void MainWindow::on_addnat_pushButton_clicked()
{
    int row = ui->tableWidget_nat->rowCount();
    ui->tableWidget_nat->insertRow(row);
}

void MainWindow::on_delnat_pushButton_clicked()
{
    int rowIndex = ui->tableWidget_nat->currentRow();
    if (rowIndex != -1)
        ui->tableWidget_nat->removeRow(rowIndex);
}

void MainWindow::on_applynat_pushButton_clicked()
{
    unsigned firewall_ip, nat_ip, inet_ip, mask;
    firewall_ip = ipstr_to_num(ui->lineEdit->text().toLatin1().data());
    Convert(inet_ip, mask, ui->lineEdit_2->text().toLatin1().data());
    SetNat(inet_ip, mask, firewall_ip);
    unsigned short nat_port, firewall_port;
    nnum = 0; 
    int row = ui->tableWidget_nat->rowCount();
    for(int i = 0; i < row; i++){
        nat_ip = ipstr_to_num(ui->tableWidget_nat->item(i, 0)->text().toLatin1().data());
        nat_port = ui->tableWidget_nat->item(i, 1)->text().toShort();
        firewall_port = ui->tableWidget_nat->item(i, 2)->text().toShort();
        AddNatRule(nat_ip, nat_port, firewall_port);
    }
    SendNatRules();
}



void MainWindow::on_pushButton_flashlink_clicked()
{
    GetConnections();
    ui->tableWidget_status->setRowCount(0);
    int row;
    char buff[20];
    for(int i = 0; i < cnum; i++){
        row = ui->tableWidget_status->rowCount();
        ui->tableWidget_status->insertRow(row);
        ui->tableWidget_status->setItem(i, 0,new QTableWidgetItem(QString(QLatin1String(addr_from_net(buff, cons[i].src_ip)))));
        ui->tableWidget_status->setItem(i, 1,new QTableWidgetItem(QString(QLatin1String(addr_from_net(buff, cons[i].dst_ip)))));
        ui->tableWidget_status->setItem(i, 2,new QTableWidgetItem(QString::number(cons[i].src_port)));
        ui->tableWidget_status->setItem(i, 3,new QTableWidgetItem(QString::number(cons[i].dst_port)));
        ui->tableWidget_status->setItem(i, 4,new QTableWidgetItem(QString::number(cons[i].protocol)));
    }
    ui->tableWidget_status->show();
}

void MainWindow::on_pushButton_flashlog_clicked()
{
    GetLogs();
    ui->tableWidget_logs->setRowCount(0);
    int row;
    char buff[20];
    for(int i = 0; i < lnum; i++){
        row = ui->tableWidget_logs->rowCount();
        ui->tableWidget_logs->insertRow(row);
        qDebug() << QString(QLatin1String(addr_from_net(buff, logs[i].src_ip))) << endl;
        qDebug() << QString(QLatin1String(addr_from_net(buff, logs[i].dst_ip))) << endl;
        qDebug() << QString::number(logs[i].src_port) << endl;
        qDebug() << QString::number(logs[i].dst_port) << endl;
        qDebug() << QString::number(logs[i].protocol) << endl;
        qDebug() << QString::number(logs[i].action) << endl;
        ui->tableWidget_logs->setItem(i, 0,new QTableWidgetItem(QString(QLatin1String(addr_from_net(buff, logs[i].src_ip)))));
        ui->tableWidget_logs->setItem(i, 1,new QTableWidgetItem(QString(QLatin1String(addr_from_net(buff, logs[i].dst_ip)))));
        ui->tableWidget_logs->setItem(i, 2,new QTableWidgetItem(QString::number(logs[i].src_port)));
        ui->tableWidget_logs->setItem(i, 3,new QTableWidgetItem(QString::number(logs[i].dst_port)));
        ui->tableWidget_logs->setItem(i, 4,new QTableWidgetItem(QString::number(logs[i].protocol)));
        ui->tableWidget_logs->setItem(i, 5,new QTableWidgetItem(QString::number(logs[i].action)));
    }
    ui->tableWidget_logs->show();
}


void MainWindow::InitRuleTable(){
    QStringList header;
    header << "source ip" <<"dest ip" << "src port" << "dst port" << "protocol" << "action" << "has log";
    ui->tableWidget_rule->setColumnCount(7);
    ui->tableWidget_rule->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tableWidget_rule->setFocusPolicy(Qt::NoFocus);
    QHeaderView *headerView = ui->tableWidget_rule->verticalHeader();
    headerView->setHidden(true);
    ui->tableWidget_rule->setHorizontalHeaderLabels(header);
    ui->tableWidget_rule->horizontalHeader()->resizeSection(0,160);
    ui->tableWidget_rule->horizontalHeader()->resizeSection(1,160);
    ui->tableWidget_rule->horizontalHeader()->resizeSection(2,70);
    ui->tableWidget_rule->horizontalHeader()->resizeSection(3,70);
    ui->tableWidget_rule->horizontalHeader()->resizeSection(4,70);
    ui->tableWidget_rule->horizontalHeader()->resizeSection(5,60);
    ui->tableWidget_rule->horizontalHeader()->resizeSection(6,60);
}



void MainWindow::InitNatTable(){
    QStringList header;
    header << "nat ip" << "nat port" << "firewall port";
    ui->tableWidget_nat->setColumnCount(3);
    ui->tableWidget_nat->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tableWidget_nat->setFocusPolicy(Qt::NoFocus);
    QHeaderView *headerView = ui->tableWidget_nat->verticalHeader();
    headerView->setHidden(true);
    ui->tableWidget_nat->setHorizontalHeaderLabels(header);
    ui->tableWidget_nat->horizontalHeader()->resizeSection(0,200);
    ui->tableWidget_nat->horizontalHeader()->resizeSection(1,100);
    ui->tableWidget_nat->horizontalHeader()->resizeSection(2,100);
}

void MainWindow::InitStatuTable(){
    QStringList header;
    header << "source ip" <<"dest ip" << "src port" << "dst port" << "protocol";
    ui->tableWidget_status->setColumnCount(5);
    ui->tableWidget_status->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tableWidget_status->setFocusPolicy(Qt::NoFocus);
    QHeaderView *headerView = ui->tableWidget_status->verticalHeader();
    headerView->setHidden(true);
    ui->tableWidget_status->setHorizontalHeaderLabels(header);
    ui->tableWidget_status->horizontalHeader()->resizeSection(0,187);
    ui->tableWidget_status->horizontalHeader()->resizeSection(1,187);
    ui->tableWidget_status->horizontalHeader()->resizeSection(2,90);
    ui->tableWidget_status->horizontalHeader()->resizeSection(3,90);
    ui->tableWidget_status->horizontalHeader()->resizeSection(4,90);
}

void MainWindow::InitLogTable(){
    QStringList header;
    header << "source ip" <<"dest ip" << "src port" << "dst port" << "protocol" << "action";
    ui->tableWidget_logs->setColumnCount(6);
    ui->tableWidget_logs->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tableWidget_logs->setFocusPolicy(Qt::NoFocus);
    QHeaderView *headerView = ui->tableWidget_logs->verticalHeader();
    headerView->setHidden(true);
    ui->tableWidget_logs->setHorizontalHeaderLabels(header);
    ui->tableWidget_logs->horizontalHeader()->resizeSection(0,165);
    ui->tableWidget_logs->horizontalHeader()->resizeSection(1,165);
    ui->tableWidget_logs->horizontalHeader()->resizeSection(2,80);
    ui->tableWidget_logs->horizontalHeader()->resizeSection(3,80);
    ui->tableWidget_logs->horizontalHeader()->resizeSection(4,80);
    ui->tableWidget_logs->horizontalHeader()->resizeSection(5,80);
}

void MainWindow::on_accept_radioButton_clicked()
{
    SetDefault(true);
}

void MainWindow::on_reject_radioButton_clicked()
{
    SetDefault(false);
}
