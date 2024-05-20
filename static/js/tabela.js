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