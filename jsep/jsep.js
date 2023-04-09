/*
 *  Copyright (c) 2015 The WebRTC project authors. All Rights Reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree.
 */

'use strict';

window.onload = function(evt) {
  initialize_page();
}

let sip_url="ws://127.0.0.1:8802"

let playing=false;

callButton.disabled = false;
hangupButton.disabled = true;
callButton.addEventListener('click', call);
hangupButton.addEventListener('click', hangup);

function initialize_page() {
  hangupButton.disabled = true;
  callButton.disabled = false;
}

let startTime;

const cameraView = document.getElementById('cameraView');
const audioPlayer = document.getElementById('audioPlayer');

cameraView.addEventListener('loadedmetadata', function() {
  console.log(`Remote video videoWidth: ${this.videoWidth}px,  videoHeight: ${this.videoHeight}px`);
});

cameraView.addEventListener('resize', () => {
  console.log(`Remote video size changed to ${cameraView.videoWidth}x${cameraView.videoHeight}`);
  // We'll use the first onsize callback as an indication that video has started
  // playing out.
  if (startTime) {
    const elapsedTime = window.performance.now() - startTime;
    console.log('Setup time: ' + elapsedTime.toFixed(3) + 'ms');
    startTime = null;
  }
});

let pc2;
const offerOptions = {
  offerToReceiveAudio: 1,
  offerToReceiveVideo: 1
};

function getName(pc) {
  return 'pc2';
}

async function set_remote_offer(sdp) {
  const offer = new RTCSessionDescription({type:"offer", sdp:sdp});
  console.log(`Offer to pc2\n${offer.sdp}`);
  try {
    await pc2.setRemoteDescription(offer);
    onSetRemoteSuccess(pc2);
  } catch (e) {
    onSetSessionDescriptionError(e);
  }
  const answer = await pc2.createAnswer();
  try {
    await pc2.setLocalDescription(answer);
  } catch (e) {
    onSetSessionDescriptionError(e);
  }
  console.log(`local description:\n${pc2.localDescription.sdp}`);
  playing = true;
}

function remote_timeout() {
  console.log(" * remote_timeout *");
}

async function get_remote_offer(url) {
  var ws_timer = setTimeout(remote_timeout, 5000);
  const socket = new WebSocket(url);
  socket.onmessage = function(evt) {
	clearTimeout(ws_timer);
    set_remote_offer(evt.data);
    socket.close();
  };
  socket.onclose = function(evt) {
    console.log("websocket get sdp closed");
  }
  // send candidate once Connection opened
  socket.addEventListener('open', function (evt) {
    // sdp includes candidates
    socket.send("get sdp\r\n\r\n");
  });
}

async function call() {
  callButton.disabled = true;
  hangupButton.disabled = false;
  console.log('Starting call');
  startTime = window.performance.now();
  pc2 = new RTCPeerConnection();
  console.log('Created remote peer connection object pc2');
  pc2.addEventListener('track', gotRemoteStream);
  get_remote_offer(sip_url);
}

function onSetRemoteSuccess(pc) {
  console.log(`${getName(pc)} setRemoteDescription complete`);
}

function onSetSessionDescriptionError(error) {
  console.log(`Failed to set session description: ${error.toString()}`);
}

function volumeChanged(val) {
  if(val == 0 ) document.getElementById('speaker').innerHTML="&#128263;";
  else if(val < 4 ) document.getElementById('speaker').innerHTML="&#128264;";
  else if(val < 6 ) document.getElementById('speaker').innerHTML="&#128265;";
  else document.getElementById('speaker').innerHTML="&#128266;";
  audioPlayer.muted = cameraView.muted = (val == 0);
  audioPlayer.volume = cameraView.volume = val/10.0;
}

function gotRemoteStream(e) {
  if (e.track.kind=='video' && cameraView.srcObject !== e.streams[0]) {
    cameraView.srcObject = e.streams[0];
    console.log('pc2 received remote video stream');
  } else
  if (e.track.kind=='audio' && audioPlayer.srcObject !== e.streams[0]) {
    audioPlayer.srcObject = e.streams[0];
    audioVolume.disabled = false;
    console.log('pc2 received remote audio stream');
  }
}

function hangup() {
  console.log('Ending call');
  pc2.close();
  pc2 = null;
  initialize_page();
  cameraView.load(); // reset video window
}
