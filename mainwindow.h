#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "arp_spoofer.h"
#include "dns_spoofer.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();
    void setup_validation();

private slots:
    void on_pushButton_poison_clicked();

    void on_pushButton_spoof_clicked();

    void on_pushButton_refresh_targets_clicked();

    void on_pushButton_refresh_spoof_list_clicked();

private:
    Ui::MainWindow *ui;
    ARP_Spoofer arp_spoofer;
    DNS_Spoofer dns_spoofer;
};

#endif // MAINWINDOW_H
