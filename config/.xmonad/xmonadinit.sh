#!/bin/bash

trayer --edge top --align right --SetDockType true --SetPartialStrut true \
     --expand true --width 10 --transparent true --tint 0x191970 --height 12 &
 
nm-applet --sm-disable &
gnome-power-manager



