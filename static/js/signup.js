$('#check_username').click(function(){
	console.log('shit');
	
	$.ajax({
		url: '/user_check'
		type: 'POST',
		data: {username: $('#signup_username').value()}
		success: function(data){
				$('#check_username').hide();
				$('#verify_icon_image').show();
				$('#icon_description').show();
		}			
	)};
});
