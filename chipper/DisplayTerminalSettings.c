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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>

#include "DisplayTerminalSettings.h"

int DisplayTermFlags_I(tcflag_t Flags)
{
   if (Flags & IGNBRK) dprintf(STDERR_FILENO, "IGNBRK ");
   if (Flags & BRKINT) dprintf(STDERR_FILENO, "BRKINT ");
   if (Flags & IGNPAR) dprintf(STDERR_FILENO, "IGNPAR ");
   if (Flags & PARMRK) dprintf(STDERR_FILENO, "PARMRK ");
   if (Flags & INPCK) dprintf(STDERR_FILENO, "INPCK ");
   if (Flags & ISTRIP) dprintf(STDERR_FILENO, "ISTRIP ");
   if (Flags & INLCR) dprintf(STDERR_FILENO, "INLCR ");
   if (Flags & IGNCR) dprintf(STDERR_FILENO, "IGNCR ");
   if (Flags & ICRNL) dprintf(STDERR_FILENO, "CRNL ");
   if (Flags & IUCLC) dprintf(STDERR_FILENO, "IUCLC ");
   if (Flags & IXON) dprintf(STDERR_FILENO, "IXON ");
   if (Flags & IXANY) dprintf(STDERR_FILENO, "IXANY ");
   if (Flags & IXOFF) dprintf(STDERR_FILENO, "IXOFF ");
   if (Flags & IMAXBEL) dprintf(STDERR_FILENO, "IMAXBEL ");
   return(0);
}

int DisplayTermFlags_O(tcflag_t Flags)
{
   if (Flags & OPOST) dprintf(STDERR_FILENO, "OPOST ");
   if (Flags & OLCUC) dprintf(STDERR_FILENO, "OLCUC ");
   if (Flags & ONLCR) dprintf(STDERR_FILENO, "ONLCR ");
   if (Flags & OCRNL) dprintf(STDERR_FILENO, "OCRNL ");
   if (Flags & ONOCR) dprintf(STDERR_FILENO, "ONOCR ");
   if (Flags & ONLRET) dprintf(STDERR_FILENO, "ONLRET ");
   if (Flags & OFILL) dprintf(STDERR_FILENO, "OFILL ");
   if (Flags & OFDEL) dprintf(STDERR_FILENO, "OFDEL ");
   if (Flags & NLDLY) dprintf(STDERR_FILENO, "NLDLY ");
   if (Flags & CRDLY) dprintf(STDERR_FILENO, "CRDLY ");
   if (Flags & TABDLY) dprintf(STDERR_FILENO, "TABDLY ");
   if (Flags & BSDLY) dprintf(STDERR_FILENO, "BSDLY ");
   if (Flags & VTDLY) dprintf(STDERR_FILENO, "VTDLY ");
   if (Flags & FFDLY) dprintf(STDERR_FILENO, "FFDLY ");
   return(0);
}

int DisplayTermFlags_C(tcflag_t Flags)
{
   if (Flags & CSIZE)
   {
      dprintf(STDERR_FILENO, "CSIZE ");
      if (Flags & CS5 & CSIZE) dprintf(STDERR_FILENO, "CS5 ");
      if (Flags & CS6 & CSIZE) dprintf(STDERR_FILENO, "CS6 ");
      if (Flags & CS7 & CSIZE) dprintf(STDERR_FILENO, "CS7 ");
      if (Flags & CS8 & CSIZE) dprintf(STDERR_FILENO, "CS8 ");
   }
   if (Flags & CSTOPB) dprintf(STDERR_FILENO, "CSTOPB ");
   if (Flags & CREAD) dprintf(STDERR_FILENO, "CREAD ");
   if (Flags & PARENB) dprintf(STDERR_FILENO, "PARENB ");
   if (Flags & PARODD) dprintf(STDERR_FILENO, "PARODD ");
   if (Flags & HUPCL) dprintf(STDERR_FILENO, "HUPCL ");
   if (Flags & CLOCAL) dprintf(STDERR_FILENO, "CLOCAL ");
   if (Flags & CIBAUD) dprintf(STDERR_FILENO, "CIBAUD ");
   if (Flags & CRTSCTS) dprintf(STDERR_FILENO, "CRTSCTS ");
   return(0);
}

int DisplayTermFlags_L(tcflag_t Flags)
{
   if (Flags & ISIG) dprintf(STDERR_FILENO, "ISIG ");
   if (Flags & ICANON) dprintf(STDERR_FILENO, "ICANON ");
   if (Flags & XCASE) dprintf(STDERR_FILENO, "XCASE ");
   if (Flags & ECHO) dprintf(STDERR_FILENO, "ECHO ");
   if (Flags & ECHOE) dprintf(STDERR_FILENO, "ECHOE ");
   if (Flags & ECHOK) dprintf(STDERR_FILENO, "ECHOK ");
   if (Flags & ECHONL) dprintf(STDERR_FILENO, "ECHONL ");
   if (Flags & ECHOCTL) dprintf(STDERR_FILENO, "ECHOCTL ");
   if (Flags & ECHOPRT) dprintf(STDERR_FILENO, "ECHOPRT ");
   if (Flags & ECHOKE) dprintf(STDERR_FILENO, "ECHOKE ");
   if (Flags & FLUSHO) dprintf(STDERR_FILENO, "FLUSHO ");
   if (Flags & NOFLSH) dprintf(STDERR_FILENO, "NOFLSH ");
   if (Flags & TOSTOP) dprintf(STDERR_FILENO, "TOSTOP ");
   if (Flags & PENDIN) dprintf(STDERR_FILENO, "PENDIN ");
   if (Flags & IEXTEN) dprintf(STDERR_FILENO, "IEXTEN ");
   return(0);
}

int DisplayAllTermSettings(struct termios *tios) {
   dprintf(STDERR_FILENO, "iflag = 0x%X: ", tios->c_iflag);
   DisplayTermFlags_I(tios->c_iflag);
   dprintf(STDERR_FILENO, "\n");
   dprintf(STDERR_FILENO, "oflag = 0x%X: ", tios->c_oflag);
   DisplayTermFlags_O(tios->c_oflag);
   dprintf(STDERR_FILENO, "\n");
   dprintf(STDERR_FILENO, "cflag = 0x%X: ", tios->c_cflag);
   DisplayTermFlags_C(tios->c_cflag);
   dprintf(STDERR_FILENO, "\n");
   dprintf(STDERR_FILENO, "lflag = 0x%X: ", tios->c_lflag);
   DisplayTermFlags_L(tios->c_lflag);
   dprintf(STDERR_FILENO, "\n");
   return(0);
}

int GetTermSettings(int Port)
{
   struct termios termios;

   tcgetattr(Port, &termios);

   DisplayAllTermSettings(&termios);
   return(0);
}
