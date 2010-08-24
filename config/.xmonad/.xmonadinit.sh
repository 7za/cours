#!/bin/bash

trayer --edge top --align right --SetDockType true --SetPartialStrut true \
     --expand true --width 10 --transparent true --tint 0x191970 --height 12 &


pidgin &

gnome-screensaver &

nm-applet --sm-disable &
sleep 3
gnome-power-manager

/usr/bin/xmobar /home/fred/.xmobarrc
