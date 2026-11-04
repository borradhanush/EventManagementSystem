const video = document.getElementById('camera');
const canvas = document.getElementById('snapshot');
const startButton = document.getElementById('capture');
const photoButton = document.getElementById('take-photo');
const statusText = document.getElementById('camera-status');
let stream;

startButton.addEventListener('click', async () => {
  try {
    stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'user' } });
    video.srcObject = stream;
    photoButton.disabled = false;
    statusText.textContent = 'Camera is ready.';
  } catch (error) {
    statusText.textContent = 'Camera access failed. Check browser permissions or upload an image instead.';
  }
});

photoButton.addEventListener('click', async () => {
  canvas.width = video.videoWidth;
  canvas.height = video.videoHeight;
  canvas.getContext('2d').drawImage(video, 0, 0);
  statusText.textContent = 'Checking image…';
  const response = await fetch(window.location.pathname, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ image_data: canvas.toDataURL('image/jpeg', 0.9) })
  });
  const result = await response.json();
  statusText.textContent = result.message;
  if (result.ok) window.location.reload();
});
