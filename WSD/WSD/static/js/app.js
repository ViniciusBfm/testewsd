//menu 
document.addEventListener('DOMContentLoaded', function () {
    var menubtn = document.querySelector(".menu-btn");
    var menu = document.querySelector(".menu");

    menubtn.addEventListener('click', function () {
        // Alternar a visibilidade do menu
        if (menu.style.display === 'none') {
            menu.style.display = 'block';
        } else {
            menu.style.display = 'none';
        }
    });
});

const openCameraBtn = document.getElementById('openCamera');
const closeCameraBtn = document.getElementById('closeCamera');
const videoElement = document.getElementById('video');

openCameraBtn.addEventListener('click', async () => {
    console.log('Botão Abrir Câmera clicado');
    try {
        const stream = await navigator.mediaDevices.getUserMedia({ video: true });
        videoElement.srcObject = stream;
        closeCameraBtn.style.display = 'inline-block';
        openCameraBtn.style.display = 'none';
    } catch (err) {
        console.error('Erro ao acessar a câmera:', err);
    }
});

closeCameraBtn.addEventListener('click', () => {
    console.log('Botão Fechar Câmera clicado');
    const stream = videoElement.srcObject;
    if (stream) {
        const tracks = stream.getTracks();
        tracks.forEach(track => track.stop());
        videoElement.srcObject = null;
        closeCameraBtn.style.display = 'none';
        openCameraBtn.style.display = 'inline-block';
    }
});




//Solicitações aprovadas tabela 
$(document).ready(function () {
    // Inicialize DataTable para a tabela de aprovações
    $('#aprovadas-table').DataTable({
        language: {
            url: 'https://cdn.datatables.net/plug-ins/1.10.25/i18n/Portuguese-Brasil.json'
        },
        order: [[1, 'asc']] // 0 é o índice da coluna de data, 'desc' para ordenação descendente
        // Adicione outras opções de DataTables conforme necessário
    });
});

 

