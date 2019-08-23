/*
   DisplayTerminalSettings - Display the settings of a terminal
   Copyright (C) 2004 Frank Sorenson (frank@tuxrocks.com)

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   as published by the Free Software Foundation; either version 2
   of the License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*/

#ifndef __DTS_H__
#define __DTS_H__

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>

int DisplayTermFlags_I(tcflag_t Flags);
int DisplayTermFlags_O(tcflag_t Flags);
int DisplayTermFlags_C(tcflag_t Flags);
int DisplayTermFlags_L(tcflag_t Flags);
int DisplayAllTermSettings(struct termios *tios);
int GetTermSettings(int Port);

#endif
