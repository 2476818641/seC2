#ifndef LANGMANAGER_H
#define LANGMANAGER_H

#include <QObject>
#include <QTranslator>

class LangManager : public QObject
{
    Q_OBJECT

public:
    static LangManager& instance();

    // "zh_CN" or "en_US"
    QString currentLanguage() const;
    void    switchLanguage(const QString &langCode);

Q_SIGNALS:
    void languageChanged();

private:
    explicit LangManager(QObject *parent = nullptr);

    QTranslator m_translator;
    QString     m_current;
};

#endif // LANGMANAGER_H
