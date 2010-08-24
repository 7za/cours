import XMonad
import XMonad.Hooks.DynamicLog
import XMonad.Hooks.ManageDocks
import XMonad.Layout.NoBorders
import XMonad.Layout.Circle
import XMonad.Layout.Grid
import XMonad.Util.Run(spawnPipe)
import XMonad.Util.EZConfig(additionalKeys)
import XMonad.Actions.CycleWS
import System.IO
import qualified Data.Map        as M
import qualified XMonad.StackSet as W

     

myDmenu =
    "exec `dmenu_path  | dmenu -nb '#000000' -nf '#777777' -sb '#000000' -sf '#ee9a00'`"




myWorkspaces    = ["code","web","chat","misc","private"]



myLayout = smartBorders $ ( avoidStruts $ tiled ||| Mirror tiled ||| Circle ||| Full ) ||| Full
    where
    tiled   = Tall nmaster delta ratio
    nmaster = 1
    ratio   = 3/5
    delta   = 3/100



main = do
    xmproc <- spawnPipe "/usr/bin/xmobar /home/fred/.xmobarrc"
    xmproc2 <- spawnPipe "/home/fred/.xmonad/xmonadinit.sh"
    xmonad $ defaultConfig
        { manageHook = manageDocks <+> manageHook defaultConfig
        , layoutHook = myLayout
        , logHook = dynamicLogWithPP $ xmobarPP
                        { ppOutput = hPutStrLn xmproc
                         , ppTitle = xmobarColor "#ee9a00" "" . shorten 50
                        }
        , focusedBorderColor = "#ee9a00"
        , normalBorderColor  = "#222222"
        , workspaces         = myWorkspaces
        } `additionalKeys`
        [ ((mod1Mask .|. shiftMask, xK_l), spawn "gnome-screensaver-command --lock")
        , ((mod1Mask, xK_p), spawn myDmenu)
        , ((mod1Mask, xK_Right), nextWS)
        , ((mod1Mask, xK_Left), prevWS)
        , ((mod1Mask .|. shiftMask, xK_Right), shiftToNext >> nextWS)
        , ((mod1Mask .|. shiftMask, xK_Left), shiftToPrev >> prevWS)
        ]
