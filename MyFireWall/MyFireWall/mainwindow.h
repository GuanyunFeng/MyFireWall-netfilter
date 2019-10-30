#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QString>
#include <QStringList>
#include <QHeaderView>
#include <QDebug>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT
    
public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();
    void InitRuleTable();
    void InitNatTable();
    void InitStatuTable();
    void InitLogTable();
    
private slots:
    void on_add_pushButton_clicked();

    void on_del_pushButton_clicked();

    void on_addnat_pushButton_clicked();

    void on_delnat_pushButton_clicked();

    void on_pushButton_flashlink_clicked();

    void on_pushButton_flashlog_clicked();

    void on_applynat_pushButton_clicked();

    void on_apply_pushButton_clicked();

    void on_accept_radioButton_clicked();

    void on_reject_radioButton_clicked();

private:
    Ui::MainWindow *ui;
};

#endif // MAINWINDOW_H
