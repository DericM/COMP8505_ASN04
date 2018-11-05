#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}


void MainWindow::setup_validation(){
    QString ipRange = "(?:[0-1]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])";
    // You may want to use QRegularExpression for new code with Qt 5 (not mandatory).
    QRegExp ipRegex ("^" + ipRange
                     + "\\." + ipRange
                     + "\\." + ipRange
                     + "\\." + ipRange + "$");
    QRegExpValidator *ipValidator = new QRegExpValidator(ipRegex, this);
    ui->lineEdit_router->setValidator(ipValidator);
    ui->lineEdit_victim->setValidator(ipValidator);
    ui->lineEdit_redirect->setValidator(ipValidator);

}

void MainWindow::on_pushButton_poison_clicked()
{
    QString router_ip = ui->lineEdit_router->text();
    QString victim_ip = ui->lineEdit_victim->text();
    arp_spoofer.add_victim(router_ip.toStdString(), victim_ip.toStdString());

    QString newLine;
    newLine.append(router_ip);
    newLine.append(" : ");
    newLine.append(victim_ip);

    ui->textBrowser_target_list->append(newLine);
}

void MainWindow::on_pushButton_spoof_clicked()
{
    QString target_domain = ui->lineEdit_target->text();
    QString redirect_ip = ui->lineEdit_redirect->text();

    dns_spoofer.add_target(target_domain.toStdString(), redirect_ip.toStdString());

    QString newLine;
    newLine.append(target_domain);
    newLine.append(" : ");
    newLine.append(redirect_ip);


    ui->textBrowser_spoof_list->append(newLine);
}

void MainWindow::on_pushButton_refresh_targets_clicked()
{
    arp_spoofer.reset();
    ui->textBrowser_target_list->clear();
}

void MainWindow::on_pushButton_refresh_spoof_list_clicked()
{
    dns_spoofer.reset();
    ui->textBrowser_spoof_list->clear();
}
