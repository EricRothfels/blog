
var loginHtml = '<div class="modal-div">\
        <p class="close-modal">x</p>\
        <h2>Sign In</h2>\
    <form id="loginForm" method="post">\
      <table><tr>\
          <td class="label">Username</td>\
          <td><input type="text" name="username""></td>\
        </tr><tr>\
          <td class="label">Password</td>\
          <td><input type="password" name="password" value=""></td>\
          <td class="error"></td>\
        </tr></table>\
      <input type="submit">\
    </form></div>';
    
var registerHtml = '<div class="modal-div">\
        <p class="close-modal">x</p>\
        <h2>Register for an EpicBlog Account!</h2>\
    <form method="post">\
    <input type="text" name="next_url" value="{{next_url}}" hidden>\
      <table><tr>\
          <td class="label">Username</td>\
          <td><input type="text" name="username" value=""></td>\
          <td class="error"></td>\
        </tr><tr>\
          <td class="label">Password</td>\
          <td><input type="password" name="password" value=""></td>\
          <td class="error"></td>\
        </tr><tr>\
          <td class="label">Verify Password</td>\
          <td><input type="password" name="verify" value=""></td>\
          <td class="error"></td>\
        </tr><tr>\
          <td class="label">Email (optional)</td>\
          <td><input type="text" name="email" value=""></td>\
          <td class="error"></td>\
        </tr></table>\
    <input type="submit">\
    </form></div>';


function bindRegisterClickHandler() {
    // bind to the click event
    $("#register").click(function(event) {
        // prevent default event
        event.preventDefault();
        
        displayModal(registerHtml);
    });
}

function bindLogInClickHandler() {
    
    // bind to the click event
    $("#signIn").click(function(event) {
        // prevent default event
        event.preventDefault();
        
        displayModal(loginHtml);
        
        $("#loginForm").submit(function(formEvent) {
            formEvent.preventDefault();
        
            var form = $(this);
            // serialize the data in the form
            var serializedData = form.serialize();
        
            $.ajax({
                type: "POST",
                url: "/blog/login",
                data: serializedData,
                dataType: "json",
                success: function(data) {
                    // Call this function on success
                    console.log("login ajax Success");
                    if (data.status === "error") {
                        $('.error').text(data.msg);
                    } else {
                        if (data.msg) {
                            window.location.replace(data.msg);
                        } else {
                            window.location.replace("/blog/welcome");
                        }
                    }
                },
                error: function(data) {
                    console.log("login ajax Error:");
                    console.log(data);
                }
            });
        });
    });
}

function displayModal(htmlString) {
    $(".modal").html(htmlString);
        $(".modal").show();
        // disable scrollbar
        $("body").css("overflow", "hidden");
        
        // close modal button
        $(".close-modal").click(function() {
            $(".modal").hide();
            $("body").css("overflow", "visible");
        });
}
