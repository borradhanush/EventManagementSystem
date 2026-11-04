(() => {
  const resultBox = document.getElementById('gate-result');
  const statusText = document.getElementById('gate-camera-status');
  const video = document.getElementById('gate-camera');
  const canvas = document.getElementById('gate-snapshot');
  const cameraSelect = document.getElementById('gate-camera-select');
  const startButton = document.getElementById('gate-start-camera');
  const captureButton = document.getElementById('gate-capture');
  const captureHelp = document.querySelector('.gate-face-panel .gate-capture-help');
  const preview = document.querySelector('.gate-face-panel .gate-video-frame');
  const qrVideo = document.getElementById('gate-qr-camera');
  const qrCanvas = document.getElementById('gate-qr-snapshot');
  const qrCameraSelect = document.getElementById('gate-qr-camera-select');
  const qrStartButton = document.getElementById('gate-qr-start-camera');
  const qrCaptureButton = document.getElementById('gate-qr-capture');
  const qrStatusText = document.getElementById('gate-qr-camera-status');
  const qrPreview = qrVideo.closest('.gate-video-frame');
  const qrCaptureHelp = document.querySelector('.gate-qr-camera-block .gate-capture-help');
  let stream = null;
  let qrStream = null;
  let busy = false;
  captureHelp.hidden = !captureButton.disabled;
  qrCaptureHelp.hidden = !qrCaptureButton.disabled;

  function updateStatus(element, message, active) {
    const visibleMessage = message || (active ? 'Camera is ready.' : 'Camera is off.');
    element.textContent = visibleMessage;
    element.classList.remove('is-off', 'is-pending', 'is-ready', 'is-error');
    if (!active && (!message || /camera is off/i.test(message))) {
      element.classList.add('is-off');
    } else if (/opening camera|checking|verifying|starting/i.test(visibleMessage)) {
      element.classList.add('is-pending');
    } else if (/camera is ready|verified|check complete/i.test(visibleMessage)) {
      element.classList.add('is-ready');
    } else {
      element.classList.add('is-error');
    }
  }

  function setStatus(message) {
    updateStatus(statusText, message, Boolean(stream));
  }

  function setQrStatus(message) {
    updateStatus(qrStatusText, message, Boolean(qrStream));
  }

  function stopCamera() {
    if (stream) {
      stream.getTracks().forEach(track => track.stop());
      stream = null;
    }
    video.srcObject = null;
    preview.classList.remove('is-active');
    captureButton.disabled = true;
    captureHelp.hidden = false;
  }

  function stopQrCamera() {
    if (qrStream) {
      qrStream.getTracks().forEach(track => track.stop());
      qrStream = null;
    }
    qrVideo.srcObject = null;
    qrPreview.classList.remove('is-active');
    qrCaptureButton.disabled = true;
    qrCaptureHelp.hidden = false;
  }

  function showResult(result, isFaceRequest = false) {
    const entered = result.status === 'ENTERED';
    const warning = ['ALREADY_ENTERED', 'INVALID', 'ERROR', 'FACE_ERROR'].includes(result.status);
    const faceResult = isFaceRequest || result.status === 'NO_MATCH' || (result.status === 'ENTERED' && result.method === 'FACE') || result.status === 'FACE_ERROR';
    const matched = result.status === 'ENTERED';
    resultBox.hidden = false;
    resultBox.className = `result-card ${warning ? 'warning' : (entered ? 'match' : 'no-match')}`;
    resultBox.replaceChildren();

    const icon = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    icon.setAttribute('viewBox', '0 0 24 24');
    icon.setAttribute('aria-hidden', 'true');
    const iconPath = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    iconPath.setAttribute('d', warning ? 'M12 9v4m0 4h.01M10.3 3.9 2.6 17.2A2 2 0 0 0 4.3 20h15.4a2 2 0 0 0 1.7-2.8L13.7 3.9a2 2 0 0 0-3.4 0Z' : entered ? 'M22 11.1V12a10 10 0 1 1-5.9-9.1M22 4 12 14l-3-3' : 'M12 22a10 10 0 1 1 0-20 10 10 0 0 1 0 20ZM15 9l-6 6m0-6 6 6');
    icon.append(iconPath);
    const title = document.createElement('h2');
    title.textContent = warning ? (result.status === 'ALREADY_ENTERED' ? 'Already recorded' : 'Rejected') : (faceResult ? (matched ? 'Matched' : 'Not matched') : (entered ? 'Verified' : 'Not verified'));
    const message = document.createElement('p');
    const serverMessage = String(result.message || 'Verification could not be completed.')
      .replace(/\b(?:cosine(?: similarity)?|similarity|score|distance|confidence|threshold)\b[^.!?]*(?:[.!?]|$)/gi, '')
      .trim();
    message.textContent = warning ? (serverMessage || 'This verification was rejected.') : faceResult ? (matched ? 'Entry recorded.' : 'Face could not be verified. Please try again.') : (serverMessage || 'Verification could not be completed.');
    const dismiss = document.createElement('button');
    dismiss.type = 'button';
    dismiss.className = 'gate-result-dismiss';
    dismiss.setAttribute('aria-label', 'Dismiss');
    dismiss.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m6 6 12 12M18 6 6 18"/></svg>';
    dismiss.addEventListener('click', () => { resultBox.hidden = true; });
    resultBox.append(icon, title, message, dismiss);
    requestAnimationFrame(() => resultBox.scrollIntoView({ behavior: 'smooth', block: 'center' }));
  }

  async function send(url, options, form) {
    if (busy) return null;
    busy = true;
    const qrFrame = options.body instanceof FormData && options.body.has('qr_image');
    const faceRequest = url.includes('verify-face');
    const button = faceRequest ? captureButton : qrFrame ? qrCaptureButton : form?.querySelector('[type="submit"], button:not([type])');
    const panel = form?.closest('.gate-panel') || document.querySelector(faceRequest ? '.gate-face-panel' : '.gate-qr-panel');
    const wasDisabled = Boolean(button?.disabled);
    if (button) button.disabled = true;
    panel?.setAttribute('aria-busy', 'true');
    if (faceRequest) setStatus('Checking…');
    else setQrStatus('Checking QR pass…');
    let spinner = null;
    const spinnerFrame = requestAnimationFrame(() => {
      if (!busy || !button) return;
      spinner = document.createElement('span');
      spinner.className = 'gate-button-spinner';
      spinner.setAttribute('aria-hidden', 'true');
      button.append(spinner);
    });
    try {
      const response = await fetch(url, options);
      const contentType = response.headers.get('content-type') || '';
      if (!contentType.includes('application/json')) throw new Error('Unexpected response');
      const result = await response.json();
      showResult(result, url.includes('verify-face'));
      return result;
    } catch (error) {
      showResult({ status: 'ERROR', message: 'Could not contact the gate verification route. Please try again or use the other verification method.' }, url.includes('verify-face'));
      return null;
    } finally {
      busy = false;
      cancelAnimationFrame(spinnerFrame);
      spinner?.remove();
      panel?.removeAttribute('aria-busy');
      if (button && !wasDisabled) button.disabled = false;
      setStatus('');
      setQrStatus('');
    }
  }

  async function refreshCameras() {
    if (!navigator.mediaDevices?.enumerateDevices) {
      cameraSelect.disabled = true;
      qrCameraSelect.disabled = true;
      setStatus('Camera selection is unavailable in this browser.');
      setQrStatus('Camera selection is unavailable in this browser.');
      return;
    }
    try {
      const cameras = (await navigator.mediaDevices.enumerateDevices())
        .filter(device => device.kind === 'videoinput');
      const current = cameraSelect.value;
      const currentQr = qrCameraSelect.value;
      cameraSelect.replaceChildren(new Option('Select a camera', ''));
      qrCameraSelect.replaceChildren(new Option('Select a camera', ''));
      cameras.forEach((device, index) => {
        const label = device.label || `Camera ${index + 1}`;
        cameraSelect.add(new Option(label, device.deviceId));
        qrCameraSelect.add(new Option(label, device.deviceId));
      });
      cameraSelect.disabled = cameras.length === 0;
      qrCameraSelect.disabled = cameras.length === 0;
      if (cameras.some(camera => camera.deviceId === current)) cameraSelect.value = current;
      if (cameras.some(camera => camera.deviceId === currentQr)) qrCameraSelect.value = currentQr;
      if (!cameras.length) {
        setStatus('No camera found.');
        setQrStatus('No camera found.');
      }
    } catch (error) {
      setStatus('Could not list cameras.');
      setQrStatus('Could not list cameras.');
    }
  }

  async function startCamera() {
    if (!navigator.mediaDevices?.getUserMedia) {
      setStatus('Camera access is unavailable in this browser.');
      return;
    }
    stopCamera();
    startButton.disabled = true;
    setStatus('Opening camera…');
    try {
      const deviceId = cameraSelect.value;
      const videoConstraints = deviceId ? { deviceId: { exact: deviceId } } : true;
      stream = await navigator.mediaDevices.getUserMedia({ video: videoConstraints, audio: false });
      video.srcObject = stream;
      stream.getVideoTracks()[0]?.addEventListener('ended', () => {
        stopCamera();
        setStatus('Camera disconnected. Choose another camera and try again.');
      }, { once: true });
      await video.play();
      preview.classList.add('is-active');
      captureButton.disabled = false;
      captureHelp.hidden = true;
      setStatus('Camera is ready.');
      await refreshCameras();
    } catch (error) {
      stopCamera();
      setStatus(error.name === 'NotAllowedError'
        ? 'Camera permission was denied. Allow camera access and try again.'
        : 'Could not open that camera. Choose another camera and try again.');
    } finally {
      startButton.disabled = false;
    }
  }

  async function startQrCamera() {
    if (!navigator.mediaDevices?.getUserMedia) {
      setQrStatus('Camera access is unavailable in this browser.');
      return;
    }
    stopQrCamera();
    qrStartButton.disabled = true;
    setQrStatus('Opening camera…');
    try {
      const deviceId = qrCameraSelect.value;
      const videoConstraints = deviceId ? { deviceId: { exact: deviceId } } : true;
      qrStream = await navigator.mediaDevices.getUserMedia({ video: videoConstraints, audio: false });
      qrVideo.srcObject = qrStream;
      qrStream.getVideoTracks()[0]?.addEventListener('ended', () => {
        stopQrCamera();
        setQrStatus('Camera disconnected. Choose another camera.');
      }, { once: true });
      await qrVideo.play();
      qrPreview.classList.add('is-active');
      qrCaptureButton.disabled = false;
      qrCaptureHelp.hidden = true;
      setQrStatus('Camera is ready. Hold a QR pass in view, then capture.');
      await refreshCameras();
    } catch (error) {
      stopQrCamera();
      setQrStatus(error.name === 'NotAllowedError'
        ? 'Camera permission was denied. Allow camera access and try again.'
        : 'Could not open that camera. Choose another camera and try again.');
    } finally {
      qrStartButton.disabled = false;
    }
  }

  document.getElementById('qr-form').addEventListener('submit', event => {
    event.preventDefault();
    send(event.currentTarget.action, { method: 'POST', body: new FormData(event.currentTarget) }, event.currentTarget);
  });

  startButton.addEventListener('click', startCamera);
  qrStartButton.addEventListener('click', startQrCamera);
  qrCameraSelect.addEventListener('change', () => {
    if (qrStream) startQrCamera();
  });
  cameraSelect.addEventListener('change', () => {
    if (stream) startCamera();
  });
  captureButton.addEventListener('click', async () => {
    if (!video.videoWidth || !video.videoHeight || busy) {
      setStatus('Wait for the camera preview before capturing.');
      return;
    }
    canvas.width = video.videoWidth;
    canvas.height = video.videoHeight;
    canvas.getContext('2d').drawImage(video, 0, 0);
    const result = await send(document.getElementById('face-form').action, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ image_data: canvas.toDataURL('image/jpeg', 0.9) })
    });
    if (result) setStatus('Face check complete.');
  });

  qrCaptureButton.addEventListener('click', async () => {
    if (!qrVideo.videoWidth || !qrVideo.videoHeight || busy) {
      setQrStatus('Wait for the camera preview before capturing.');
      return;
    }
    qrCanvas.width = qrVideo.videoWidth;
    qrCanvas.height = qrVideo.videoHeight;
    qrCanvas.getContext('2d').drawImage(qrVideo, 0, 0);
    const imageBlob = await new Promise(resolve => qrCanvas.toBlob(resolve, 'image/jpeg', 0.9));
    if (!imageBlob) {
      setQrStatus('Could not capture a frame. Try again.');
      return;
    }
    const form = document.getElementById('qr-form');
    const formData = new FormData(form);
    formData.delete('token');
    formData.append('qr_image', imageBlob, 'camera-qr-frame.jpg');
    qrCaptureButton.disabled = true;
    setQrStatus('Checking QR pass…');
    const result = await send(form.action, { method: 'POST', body: formData }, form);
    qrCaptureButton.disabled = false;
    setQrStatus(result?.status === 'ENTERED'
      ? 'QR pass verified.'
      : 'Frame checked. Adjust the QR in view and try again.');
  });

  navigator.mediaDevices?.addEventListener?.('devicechange', refreshCameras);
  setStatus('Camera is off.');
  setQrStatus('Camera is off.');
  refreshCameras();
  window.addEventListener('pagehide', () => { stopCamera(); stopQrCamera(); });
})();
