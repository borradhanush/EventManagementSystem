(() => {
  const page = document.querySelector('.face-page');
  if (!page) return;

  const video = document.getElementById('camera');
  const canvas = document.getElementById('snapshot');
  const selector = document.getElementById('camera-select');
  const captureButton = document.getElementById('take-photo');
  const status = document.getElementById('camera-status');
  const mode = page.dataset.faceMode;
  const resultBox = document.getElementById('verification-result');
  let activeStream = null;
  let changingCamera = false;
  let cameraDevices = [];

  function setStatus(message, state = '') {
    status.textContent = message;
    status.dataset.state = state;
  }

  function stopStream() {
    if (activeStream) {
      activeStream.getTracks().forEach(track => track.stop());
      activeStream = null;
    }
    if (video.srcObject) video.srcObject = null;
    captureButton.disabled = true;
  }

  function cameraErrorMessage(error) {
    if (error && (error.name === 'NotAllowedError' || error.name === 'PermissionDeniedError' || error.name === 'SecurityError')) {
      return 'Camera permission was denied. Allow camera access in your browser settings, or upload an image instead.';
    }
    if (error && (error.name === 'NotFoundError' || error.name === 'DevicesNotFoundError' || error.name === 'OverconstrainedError')) {
      return 'No camera is available. Connect a camera or upload an image instead.';
    }
    if (error && (error.name === 'NotReadableError' || error.name === 'TrackStartError' || error.name === 'AbortError')) {
      return 'The selected camera is unavailable or being used by another application. Choose another camera or upload an image.';
    }
    return 'The camera could not be started. Check browser permissions and camera availability, or upload an image.';
  }

  function chooseDevice(preferredId = '', excludeId = '') {
    const preferred = cameraDevices.find(device => device.deviceId === preferredId);
    if (preferred) return preferred;
    return cameraDevices.find(device => device.deviceId !== excludeId) || cameraDevices[0] || null;
  }

  async function refreshDevices(preferredId = selector.value, excludeId = '') {
    cameraDevices = (await navigator.mediaDevices.enumerateDevices())
      .filter(device => device.kind === 'videoinput' && device.deviceId);
    selector.replaceChildren();
    if (!cameraDevices.length) {
      const option = document.createElement('option');
      option.value = '';
      option.textContent = 'No camera found';
      selector.append(option);
      selector.disabled = true;
      return null;
    }

    cameraDevices.forEach((device, index) => {
      const option = document.createElement('option');
      option.value = device.deviceId;
      option.textContent = device.label || `Camera ${index + 1}`;
      selector.append(option);
    });
    const selected = chooseDevice(preferredId, excludeId);
    selector.value = selected ? selected.deviceId : cameraDevices[0].deviceId;
    selector.disabled = cameraDevices.length < 2;
    return selected;
  }

  function currentDeviceId(stream = activeStream) {
    const track = stream && stream.getVideoTracks()[0];
    return track && track.getSettings ? (track.getSettings().deviceId || '') : '';
  }

  function attachStream(stream) {
    activeStream = stream;
    video.srcObject = stream;
    captureButton.disabled = false;
    const track = stream.getVideoTracks()[0];
    if (track) {
      track.addEventListener('ended', async () => {
        if (changingCamera) return;
        const disconnectedId = currentDeviceId(stream);
        stopStream();
        try {
          const next = await refreshDevices('', disconnectedId);
          if (next) await startSelectedCamera(false);
          else setStatus('The selected camera disconnected. No camera is currently available; upload an image instead.', 'error');
        } catch (_) {
          setStatus('The selected camera disconnected. Choose another camera or upload an image.', 'error');
        }
      }, { once: true });
    }
    const actualId = currentDeviceId(stream);
    if (actualId) selector.value = actualId;
    setStatus('Camera is ready. Select a camera and capture when you are ready.', 'ready');
  }

  async function startSelectedCamera(retryIfRemoved = true) {
    if (changingCamera) return;
    changingCamera = true;
    const requestedId = selector.value;
    stopStream();
    setStatus('Starting selected camera…');
    try {
      const videoConstraint = requestedId ? { deviceId: { exact: requestedId } } : true;
      const nextStream = await navigator.mediaDevices.getUserMedia({ video: videoConstraint, audio: false });
      attachStream(nextStream);
    } catch (error) {
      if (retryIfRemoved && requestedId && (error.name === 'NotFoundError' || error.name === 'OverconstrainedError')) {
        try {
          const next = await refreshDevices('', requestedId);
          if (next && next.deviceId !== requestedId) {
            changingCamera = false;
            await startSelectedCamera(false);
            return;
          }
        } catch (_) {
          // Show the same friendly unavailable-camera message below.
        }
      }
      setStatus(cameraErrorMessage(error), 'error');
      await refreshDevices().catch(() => {});
    } finally {
      changingCamera = false;
    }
  }

  function renderVerification(result) {
    const section = document.createElement('section');
    section.className = `result-card ${result.matched ? 'match' : 'no-match'}`;
    const heading = document.createElement('h2');
    heading.textContent = result.label;
    const score = document.createElement('p');
    score.append('Cosine similarity: ');
    const strong = document.createElement('strong');
    strong.textContent = Number(result.similarity).toFixed(4);
    score.append(strong);
    const threshold = document.createElement('p');
    threshold.textContent = `Threshold: ${Number(result.threshold).toFixed(3)}`;
    section.append(heading, score, threshold);
    resultBox.replaceChildren(section);
  }

  async function submitCapturedFrame() {
    if (!activeStream || !video.videoWidth || !video.videoHeight) {
      setStatus('Wait for the camera preview, then capture again.', 'error');
      return;
    }
    captureButton.disabled = true;
    canvas.width = video.videoWidth;
    canvas.height = video.videoHeight;
    canvas.getContext('2d').drawImage(video, 0, 0, canvas.width, canvas.height);
    setStatus(mode === 'verify' ? 'Verifying captured image…' : 'Registering captured image…');
    try {
      const response = await fetch(window.location.pathname, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ image_data: canvas.toDataURL('image/jpeg', 0.9) })
      });
      const result = await response.json();
      if (!response.ok || !result.ok) throw new Error(result.message || 'The image could not be processed. Please try again.');
      if (mode === 'verify') {
        renderVerification(result);
        setStatus('Verification complete. The result was produced by the server.', 'ready');
      } else {
        setStatus(result.message || 'Face registration successful.', 'ready');
        window.setTimeout(() => window.location.reload(), 700);
      }
    } catch (error) {
      setStatus(error instanceof TypeError ? 'Could not reach the server. Check your connection and try again.' : error.message, 'error');
    } finally {
      captureButton.disabled = !activeStream;
    }
  }

  async function initializeCamera() {
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia || !navigator.mediaDevices.enumerateDevices) {
      selector.replaceChildren(new Option('Camera unavailable', ''));
      setStatus('This browser does not support camera selection. Upload an image instead.', 'error');
      return;
    }
    try {
      // Request permission once, then labels become available for enumeration.
      const initialStream = await navigator.mediaDevices.getUserMedia({ video: true, audio: false });
      attachStream(initialStream);
      const selected = await refreshDevices(currentDeviceId(initialStream));
      if (!selected) {
        setStatus('No camera was found. Connect a camera or upload an image instead.', 'error');
        stopStream();
      }
    } catch (error) {
      selector.disabled = true;
      setStatus(cameraErrorMessage(error), 'error');
      try {
        await refreshDevices();
      } catch (_) {
        // Camera access remains unavailable; keep the upload option usable.
      }
    }
  }

  selector.addEventListener('change', () => startSelectedCamera());
  captureButton.addEventListener('click', submitCapturedFrame);
  navigator.mediaDevices?.addEventListener?.('devicechange', async () => {
    const activeId = currentDeviceId();
    try {
      const selected = await refreshDevices(activeId);
      if (!selected) {
        stopStream();
        setStatus('No camera is currently available. Upload an image instead.', 'error');
      } else if (selected.deviceId !== activeId) {
        selector.value = selected.deviceId;
        await startSelectedCamera();
      }
    } catch (_) {
      setStatus('Could not refresh the camera list. Choose another camera or upload an image.', 'error');
    }
  });

  window.addEventListener('pagehide', stopStream, { once: true });
  window.addEventListener('beforeunload', stopStream, { once: true });
  initializeCamera();
})();
