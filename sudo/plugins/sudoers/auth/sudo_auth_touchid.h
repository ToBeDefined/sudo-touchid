//
//  sudo_auth_touchid.h
//  sudo
//
//  Created by TBD on 2019/12/23.
//  Copyright © 2019 TBD. All rights reserved.
//

#ifndef sudo_auth_touchid_h
#define sudo_auth_touchid_h

#include <stdio.h>
#include <pwd.h>

#include "sudo_plugin.h"
#include "sudo_auth.h"

int touchid_setup(struct passwd *pw, char **prompt, sudo_auth *auth);
int touchid_verify(struct passwd *pw, char *pass, sudo_auth *auth, struct sudo_conv_callback *callback);


#endif /* sudo_auth_touchid_h */
