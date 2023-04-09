Lightweight WebRTC Testbed

This project is to provide a testbed for studying WebRTC protocol suite, with
implementing WebRTC server on embedded systems as one of the main goals.

How To Use - play media file on server to show on browsers

(1) Build

$ bash ./buildme.sh

(2) Run WebRTC server

$ export/iceagent path=export/demo.mp4

(3) Open WebRTC browser client

$ [/opt/google/chrome/]chrome file://<ltwebrtc>/jsep/jsep.html

(4) Connect..
