def get_email_template(name, link):
    return """\
    <!DOCTYPE html>
    <html lang="en">
    
    <head>
        <meta charset="UTF-8">
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Document</title>
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link
            href="https://fonts.googleapis.com/css2?family=Aldrich&family=Comfortaa&family=Inter&family=Reem+Kufi:wght@500&family=Spline+Sans+Mono:wght@600&family=Titillium+Web:wght@200&display=swap"
            rel="stylesheet">
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
        h1, h3, p{
          font-size:1.2rem;
        }
        .content{
         margin-left:300px;
        }
            .main {
                display: flex;
                justify-content: center;
                margin-top: 20px;
          margin-left:400px;
            }
    
            .main img {
                margin-right: 15px;
            }
    
            h1 {
                font-family: 'Aldrich';
            }
    
            .main p {
                font-family: 'Reem Kufi';
            }
    
            .card {
                position: absolute;
                border: 1px solid #FAFCFE;
                width: 1000px;
                height: 750px;
                margin-bottom: 50px;
                top: 200px;
                background-color: #FAFCFE;
    
            }
            .card-text{
                font-family: 'Inter';
                text-align: center;
                padding: 30px;
            }
            .card-text a{
                text-decoration: none;
            }
            .bottom{
                padding-top: 25px;
            }
    
            @media screen and (max-width: 992px) {
                .card{
                    left: 0%;
                }
                .main{
            right:200px;
          }
            }
    
        </style>
    
    </head>
    
    <body style="background-image: url('https://firebasestorage.googleapis.com/v0/b/cyberneticlabs-website.appspot.com/o/background.png?alt=media&token=98963c75-a080-4354-89af-936867fd5dca');
    background-repeat: no-repeat;
    background-attachment: fixed;
    background-size: 100% 100%;">
    <div class="content">
        <div class="main">
            <img src="https://firebasestorage.googleapis.com/v0/b/cyberneticlabs-website.appspot.com/o/logo%20(6).png?alt=media&token=dbf9ba92-1782-44c1-9b8a-4cba58af1ccd" alt="ZeKoderLogo">
            <div>
                <h1>Zekoder</h1>
                <p>Your Sidekick Team</p>
            </div>
        </div>
        <div class="card">
            <div>
                <img src="https://firebasestorage.googleapis.com/v0/b/cyberneticlabs-website.appspot.com/o/mail%20icon%20ve%20background.png?alt=media&token=ebc796a0-5cc8-4de4-b5dd-25c03f402901" alt="">
            </div>
            <div class="card-text">
                <h3>Dear [user first name], </h3>
                <p style="padding-top: 15px;">Thanks for registering into ZeKoder, you are one step a head of world of possibilities. You are only required to click on this link to start using ZeKoder. If the link is inactive please copy the link below and paste it in your preferred browser address box and click go or enter.</p>
                <p style="padding-top:15px"><b> Link: <a href="">provide link</a></p></b>
                <p style="padding-top: 15px;"><b> Thanks for choosing ZeKoder</b></p>
                <p style="padding-top: 15px;"><b> ZeKoder team</b></p>
                <div class="bottom">
                    <a style="padding-right:10px ;" href=""> <img src="https://firebasestorage.googleapis.com/v0/b/cyberneticlabs-website.appspot.com/o/Logo%20(8).png?alt=media&token=f29d5e9d-87ad-49c6-b26c-8318f3320b7c" alt=""></a>
                    <a href=""><img src="https://firebasestorage.googleapis.com/v0/b/cyberneticlabs-website.appspot.com/o/Logo%20(7).png?alt=media&token=c6bec212-1343-4816-828e-68daa5385d25" alt=""></a>
                </div>
                <p style="color: #A3A3A3; padding-top:10px;">
                    Copyright © 2022, All rights reserved
                </p>
    
            </div>
        </div>
      </div>
    
    </body>
    
    </html>
    """.replace("[user first name]", name).replace("provide link", link)
