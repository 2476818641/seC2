#include <Utils/LangManager.h>
#include <QApplication>
#include <QEvent>
#include <QWidget>

LangManager& LangManager::instance()
{
    static LangManager inst;
    return inst;
}

LangManager::LangManager(QObject *parent)
    : QObject(parent), m_current("en_US")
{}

QString LangManager::currentLanguage() const
{
    return m_current;
}

void LangManager::switchLanguage(const QString &langCode)
{
    if (m_current == langCode)
        return;

    qApp->removeTranslator(&m_translator);

    if (langCode != "en_US") {
        QString path = QString(":/translations/adaptix_%1").arg(langCode);
        if (m_translator.load(path))
            qApp->installTranslator(&m_translator);
    }

    m_current = langCode;

    // Broadcast QEvent::LanguageChange to all top-level widgets
    for (QWidget *w : qApp->topLevelWidgets())
        QApplication::sendEvent(static_cast<QObject*>(w), new QEvent(QEvent::LanguageChange));

    Q_EMIT languageChanged();
}
