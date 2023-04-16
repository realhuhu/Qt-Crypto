#include <QDebug>
#include <QComboBox>
#include <QTextEdit>
#include <QLineEdit>
#include <QGridLayout>
#include <QPushButton>
#include <QApplication>
#include <QRegExpValidator>

# include "utils.h"
#include "DES/DES.h"
#include "AES/AES.h"
#include "RSA/RSA.h"
#include "ElGamal/ElGamal.h"

struct Algorithm {
    QStringList all = {"none", "DES", "AES", "RSA", "ElGamal"};
    QString current = "none";
};

int main(int argc, char *argv[]) {
    auto algorithm = new Algorithm();
    QApplication app(argc, argv);

    auto widget = new QWidget(nullptr, Qt::WindowStaysOnTopHint);
    widget->setWindowTitle("加解密");
    widget->setMinimumSize(500, 400);

    auto keyInput = new QLineEdit(widget);
    keyInput->setPlaceholderText("请选择加密方式");
    keyInput->setDisabled(true);

    auto plaintextArea = new QTextEdit(widget);
    plaintextArea->setPlaceholderText("明文");
    plaintextArea->setAcceptRichText(false);
    auto ciphertextArea = new QTextEdit(widget);
    ciphertextArea->setPlaceholderText("密文");
    ciphertextArea->setAcceptRichText(false);

    auto *submitButton = new QPushButton("确定");
    auto *encryptButton = new QPushButton("加密");
    auto *decryptButton = new QPushButton("解密");
    submitButton->setDisabled(true);
    encryptButton->setDisabled(true);
    decryptButton->setDisabled(true);

    auto *selectBox = new QComboBox();
    selectBox->addItems(algorithm->all);

    auto *layout = new QGridLayout;
    layout->addWidget(selectBox, 0, 2, 1, 1);
    layout->addWidget(keyInput, 0, 3, 1, 9);
    layout->addWidget(submitButton, 0, 12, 1, 1);
    layout->addWidget(plaintextArea, 1, 0, 3, 7);
    layout->addWidget(ciphertextArea, 1, 8, 3, 7);
    layout->addWidget(encryptButton, 4, 2, 1, 3);
    layout->addWidget(decryptButton, 4, 10, 1, 3);

    QObject::connect(
            selectBox,
            QOverload<const QString &>::of(&QComboBox::currentIndexChanged),
            [widget, keyInput, algorithm, submitButton, encryptButton, decryptButton](const QString &value)mutable {
                algorithm->current = value;
                keyInput->clear();
                encryptButton->setDisabled(true);
                decryptButton->setDisabled(true);

                if (value == "none") {
                    widget->setWindowTitle("加解密");
                    keyInput->setPlaceholderText("请选择加密方式");
                    submitButton->setDisabled(true);
                    keyInput->setDisabled(true);
                    return;
                }

                if (value == "DES") {
                    widget->setWindowTitle("DES:请输入密钥");
                    keyInput->setValidator(new QRegExpValidator(QRegExp("[0-9a-fA-F]{16}")));
                    keyInput->setPlaceholderText("请输入16位十六进制密钥");
                } else if (value == "AES") {
                    widget->setWindowTitle("AES:请输入密钥");
                    keyInput->setValidator(new QRegExpValidator(QRegExp("[0-9a-fA-F]{32}")));
                    keyInput->setPlaceholderText("请输入32位十六进制密钥");
                } else if (value == "RSA") {
                    widget->setWindowTitle("RSA:请输入私钥");
                    keyInput->setValidator(new QRegExpValidator(QRegExp("[0-9a-fA-F]{8}")));
                    keyInput->setPlaceholderText("请输入8位十六进制私钥");
                } else if (value == "ElGamal") {
                    widget->setWindowTitle("ElGamal:请输入私钥");
                    keyInput->setValidator(new QRegExpValidator(QRegExp("[0-9a-fA-F]{7}")));
                    keyInput->setPlaceholderText("请输入8位十六进制私钥");
                }

                submitButton->setDisabled(false);
                keyInput->setDisabled(false);
            });

    QObject::connect(submitButton, &QPushButton::clicked, [widget, keyInput, algorithm, encryptButton, decryptButton] {
        auto key = keyInput->text();
        if (algorithm->current == "DES") {
            key = DES::initKey(key);
        } else if (algorithm->current == "AES") {
            key = AES::initKey(key);
        } else if (algorithm->current == "RSA") {
            key = RSA::initKey(key);
        } else if (algorithm->current == "ElGamal") {
            key = ElGamal::initKey(key);
        }
        widget->setWindowTitle(algorithm->current + " " + key);
        encryptButton->setDisabled(false);
        decryptButton->setDisabled(false);
    });

    QObject::connect(encryptButton, &QPushButton::clicked, [plaintextArea, ciphertextArea, algorithm] {
        QString ciphertext;
        if (algorithm->current == "DES") {
            ciphertext = DES::encrypt(plaintextArea->toPlainText());
        } else if (algorithm->current == "AES") {
            ciphertext = AES::encrypt(plaintextArea->toPlainText());
        } else if (algorithm->current == "RSA") {
            ciphertext = RSA::encrypt(plaintextArea->toPlainText());
        } else if (algorithm->current == "ElGamal") {
            ciphertext = ElGamal::encrypt(plaintextArea->toPlainText());
        }
        ciphertextArea->setText(ciphertext);
    });

    QObject::connect(decryptButton, &QPushButton::clicked, [plaintextArea, ciphertextArea, algorithm] {
        QString plaintext;
        if (algorithm->current == "DES") {
            plaintext = DES::decrypt(ciphertextArea->toPlainText());
        } else if (algorithm->current == "AES") {
            plaintext = AES::decrypt(ciphertextArea->toPlainText());
        } else if (algorithm->current == "RSA") {
            plaintext = RSA::decrypt(ciphertextArea->toPlainText());
        }else if (algorithm->current == "ElGamal") {
            plaintext = ElGamal::decrypt(ciphertextArea->toPlainText());
        }
        plaintextArea->setText(plaintext);
    });

    widget->setLayout(layout);
    widget->show();
    return QApplication::exec();
}