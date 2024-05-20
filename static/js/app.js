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



 

