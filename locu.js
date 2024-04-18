const express=require("express");
const app=express();
const bodyParser =require( "body-parser");
const { v4: uuidv4 } = require('uuid');
const { generateJwt } = require("./jwt/genratetoken");
const cors =require("cors");
const mysql = require('mysql');
const fs =require("fs");
const bcrypt=require("bcryptjs")
require('dotenv').config();
const jwt =require("jsonwebtoken");
const { upload } = require('./middleware/fich');
const path =require( "path");
const cookieParser =require("cookie-parser");
const helmet =require("helmet");
app.use(express.static('public'));
app.use(cookieParser());
app.use(helmet());
const auth = require("./middleware/auth");
const { error, Console } = require("console");
const pool = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "newdata"
});

app.use(express.json()) ;
app.use(cors({ origin: "http://localhost:5173", credentials: true }));
app.use(cookieParser());
app.use(express.json()); // req.body
app.use(bodyParser.urlencoded({ extended: true }));

app.use(
  helmet({
    frameguard: {
      action: "deny",
    },
    xssFilter: true,
    crossOriginResourcePolicy: {
      policy: "cross-origin",
    },
  })
);


// Connexion à la base de données
pool.connect((err) => {
  if (err) {
    console.error('Erreur de connexion à la base de données:', err);
  } else {
    console.log('Connexion à la base de données établie avec succès.');
  }
});

saltOrRounds=10;
app.post("/api/v1/register", (req, res) => {
  try {
    const nom = req.body.nom;
    const prenom = req.body.prenom;
    const email = req.body.email;
    const num = req.body.num;
    const password = req.body.password;


    // Vérification si l'email est déjà utilisé
    pool.query(
      `SELECT * FROM client WHERE email = ?`,
      [email],
      (err, result) => {
        if (err) {
          return res.json({ error: "Erreur dans le serveur" });
        }
        if (result.length !== 0) {
          return res.json("L'email est déjà utilisé!");
        }

        // Générer le username à partir du nom et du prénom
        const username = nom.toLowerCase() + "_" + prenom.toLowerCase();

        // Hachage du mot de passe de l'utilisateur
        bcrypt.hash(password, saltOrRounds, (err, hash) => {
          if (err) {
            console.error("Erreur de hachage :", err);
            console.log(hash)
            return res.json({ error: "Erreur dans le hachage" });

          }

          const userId = uuidv4();
          const accountId = uuidv4();

          // Ajout des données dans la table client
          pool.query(
            "INSERT INTO client (iduser, nom, prenom, email,num) VALUES (?, ?, ?, ?,?)",
            [userId, nom, prenom,num, email],
            (err, result) => {
              if (err) {
                console.error("Erreur d'insertion dans la table client:", err);
                return res.json({ error: err.message });
              }

              // Ajout des données dans la table compte
              pool.query(
                "INSERT INTO compte (idcom, username, passeword, iduser) VALUES (?,?,?,?)",
                [accountId, username, hash,userId],
                (err, result) => {
                  if (err) {
                    console.error("Erreur d'insertion dans la table compte:", err);
                    return res.json({ error: err.message });
                  }

                  // Génération du JWT
                  const token = generateJwt({ userId, email, nom, prenom, hash });

                  // Envoi du cookie contenant le token
                  res.cookie("accessToken", token, {
                    httpOnly: true,
                    secure: true,
                  }).json({ token });
                }
              );
            }
          );
        });
      }
    );
  } catch (error) {
    console.error("Erreur lors de l'enregistrement de l'utilisateur:", error);
    res.json({ error: "Erreur interne du serveur" });
  }
});

  app.post("/api/v1/login", (req, res) => {
  const email = req.body.email;
  const password = req.body.password;
  pool.query(
    'SELECT c.iduser, c.nom, c.prenom, co.passeword FROM client c INNER JOIN compte co ON c.iduser = co.iduser WHERE c.email = ?',
    [email],
    (err, result) => {
      if (err) {
        res.json({ error: "Server Error" });
      } else if (result.length > 0) {
        const hashedPassword = result[0].passeword;
        bcrypt.compare(password, hashedPassword, (error, response) => {
          if (response) {
            const userId = result[0].iduser;
            const token = generateJwt({ userId });
            res.cookie("accessToken", token, {
              httpOnly: true,
              secure: true,
            }).json({ token });
          } else {
            res.json({ message: "Wrong password" });
          }
        });
      } else {
        res.json({ message: "User not found" });
      }
    }
  );
});

//  Logout
app.get("/api/v1/logout", (request, response) => {
  try {
    response.clearCookie("accessToken", null).send({
      authenticated: false,
      message: "Logout Successful.",
    });
  } catch (error) {
    console.log(error);
  }
});

//prover the auth
app.get("/api/v1/verif", auth, async (req, res) => {
  try {
    const userId = req.userData.userId;
    const user = await pool.query("SELECT * FROM client WHERE iduser = ?", [userId]);
    if (!user || user.length === 0) {
      return res.json({ message: "Utilisateur non trouvé dans la base de données" });
    }
    res.json({ message: "Token valide" });
    console.log(userId); // Affiche à nouveau l'ID de l'utilisateur dans la console
  } catch (error) {
    console.error("Erreur lors de la vérification du token avec l'ID de l'utilisateur:", error);
    res.json({ message: "Erreur serveur lors de la vérification du token avec l'ID de l'utilisateur" });
  }
});

// Verify the current user token if authenticated
app.get("/api/v1/that", auth, async (request, response) => {
  try {
    response.json(true);
  } catch (error) {
    console.error(error.message);
    response.send({ msg: "Unauthenticated" });
  }
});


// gerer le compte 
app.put('/api/v1/gere/compte', auth, async (req, res) => {
  try {
    const userId = req.userData.userId;
    const { nom, prenom,num,email } = req.body;

    const username = nom.toLowerCase() + "_" + prenom.toLowerCase();
    console.log(userId);
    // Mettre à jour les informations dans la table client
    pool.query(
      'UPDATE client SET prenom=?, nom=?, email=?,num=? WHERE iduser=?',
      [ nom,prenom, email,num, userId],
      (error, result) => {
        if (error) {
          console.error("Erreur lors de la mise à jour des informations dans la table client:", error);
          res.json({ error: "Erreur interne du serveur" });
        } else {
          // Mettre à jour le mot de passe dans la table compte
          pool.query(
            'UPDATE compte SET username=? WHERE iduser=?',
            [username, userId],
            (error, results) => {
              if (error) {
                console.log(userId);
                console.error("Erreur lors de la mise à jour du mot de passe dans la table compte:", error);
                res.json({ error: "Erreur interne du serveur" });
              } else {
                // Envoyer une réponse de succès si les mises à jour sont effectuées avec succès
                res.json({ message: "Mise à jour réussie" });
              }
            }
          );
        }
      }
    );
  } catch (error) {
    console.error("Erreur lors de la mise à jour des informations:", error);
    res.json({ error: "Erreur interne du serveur" });
  }
});


// Enregistrement de l'administrateur
app.post("/api/v1/admin/register", (req, res) => {
  try {
    const admin = req.body.admin;
    const password = req.body.password;

    // Hachage du mot de passe de l'administrateur
    bcrypt.hash(password, saltOrRounds, (err, hash) => {
      if (err) {
        console.error("Erreur de hachage :", err);
        return res.json({ error: "Erreur dans le hachage" });
      }

      const adminId = uuidv4();

      // Ajout des données dans la table admin
      pool.query(
        "INSERT INTO admine (adminid, admin, password) VALUES (?, ?, ?)",
        [adminId, admin, hash],
        (err, result) => {
          if (err) {
            console.error("Erreur d'insertion dans la table admin:", err);
            return res.json({ error: err.message });
          }

          // Génération du JWT
          const token = generateJwt({ adminId, admin });

          // Envoi du cookie contenant le token
          res.cookie("adminAccessToken", token, {
            httpOnly: true,
            secure: true,
          }).json({ token });
        }
      );
    });
  } catch (error) {
    console.error("Erreur lors de l'enregistrement de l'administrateur:", error);
    res.json({ error: "Erreur interne du serveur" });
  }
});

// Connexion de l'administrateur
app.post("/api/v1/admin/login", (req, res) => {
  const admin = req.body.admin;
  const password = req.body.password;

  pool.query(
    'SELECT adminid, password FROM admine WHERE admin = ?',
    [admin],
    (err, result) => {
      if (err) {
        res.json({ error: "Server Error" });
      } else if (result.length > 0) {
        const hashedPassword = result[0].password;
        bcrypt.compare(password, hashedPassword, (error, response) => {
          if (response) {
            const adminId = result[0].adminid;
            const token = generateJwt({ adminId });
            res.cookie("adminAccessToken", token, {
              httpOnly: true,
              secure: true,
            }).json({ token });
          } else {
            res.json({ message: "Wrong password" });
          }
        });
      } else {
        res.json({ message: "Admin not found" });
      }
    }
  );
});


// déposer une annonce 
app.post('/api/v1/new/annonce',auth, upload.array('file', 5), async (req, res) => {
  const userId = req.userData.userId;
  try {
    if (!req.files || req.files.length === 0) {
      return res.send({ message: "Aucun fichier n'a été téléchargé." });
    }
    const image1 = req.files[0].filename;  
    const image2 = req.files[1] ? req.files[1].filename : null;
    const image3 = req.files[2] ? req.files[2].filename : null;
    const image4 = req.files[3] ? req.files[3].filename : null;
    const image5 = req.files[4] ? req.files[4].filename : null;
   
    const dateAjout = new Date();
    const { type, surface, adresse, prix, titre, description, meuble, equipment, ville, capacite, puissance, materiel, taille ,etage,categorie, largeur, longueur,type_residence,etage_maison,etage_villa, type_villa, type_appartement} = req.body;

    if (!titre || !description || !prix || !description || !adresse) {
      return res.send({ message: "Ces champs sont requis."});
    }

    const idann = uuidv4();
    await pool.query(
      "INSERT INTO annonce (idann, titre, description, date_ajout, image1, image2, image3,image4,image5,iduser) VALUES (?, ?, ?,?, ?, ?, ?, ?,?,?)",
      [idann, titre, description,dateAjout,image1, image2, image3,image4,image5,userId]
    );
    console.log("bien inserrer dans la table annonce")
    // Insérer dans la table Bien si nécessaire
    const idB = uuidv4();
    await pool.query(
      "INSERT INTO Bien (idB,type,surface,prix,ville,adresse,userId,idann) VALUES (?,?, ?, ?, ?, ?, ?,?)",
      [idB, type,surface, prix,ville,adresse,userId, idann]
    );
    console.log("bien inserrer dans la table bien",idB)


    let idres; 
    if (type === "Résidentiel") {
        idres = uuidv4(); 
        await pool.query(
            "INSERT INTO résidentiel (idres, meuble,equipment, type_residence, idb) VALUES (?, ?, ?, ?, ?)",
            [idres, meuble,equipment,type_residence, idB]
        );

        console.log("Bien inséré dans la table résidentiel", idres); 
    
        if (type_residence === "Maison") {
            idMais = uuidv4(); 
            await pool.query(
                "INSERT INTO maison (idMais, etage_maison,idres) VALUES (?, ?, ?)",
                [idMais, etage_maison, idres]
            );
            console.log("Bien inséré dans la table maison", idMais, idres); 
        } else if (type_residence === "Villa") {
            idVil = uuidv4(); 
            await pool.query(
                "INSERT INTO villa (idVil, etage_villa, type_villa, idres) VALUES (?, ?, ?, ?)",
                [idVil, etage_villa, type_villa, idres]
            );
            console.log("Bien inséré dans la table villa", idVil, idres); 
        } else if (type_residence === "Studio") {
            idStu = uuidv4(); 
            await pool.query(
                "INSERT INTO studio (idStu, idres) VALUES (?, ?)",
                [idStu, idres]
            );
            console.log("Bien inséré dans la table studio", idStu, idres); 
        } else if (type_residence === "Appartement") {
            idApp = uuidv4(); 
            await pool.query(
                "INSERT INTO appartement (idApp, type_appartement, idres) VALUES (?, ?, ?)",
                [idApp, type_appartement, idres]
            );
            console.log("Bien inséré dans la table appartement", idApp, idres); 
        }
    }
    let idIndu; 
    if (type === "Industriel") {
       idIndu = uuidv4();
      await pool.query(
          "INSERT INTO Industriel (idIndu, capacite, puissance, materiel, taille,idb) VALUES (?, ?, ?, ?, ?, ?)",
          [idIndu, capacite, puissance,materiel, taille,idB]
      );
      console.log("bien inserrer dans la table Industriel", idIndu,idB);
  }

   
    let idComm; 
    if (type === "Commercial") {
      idComm = uuidv4();
      await pool.query(
          "INSERT INTO Commercial (idComm, equipement, etage,idb) VALUES (?, ?, ?, ?)",
          [idComm,equipment, etage,idB]
      );
      console.log("bien insérer dans la table Commercial", idComm);
  }
  let idTerr; 
  if (type === "Terrain") {
    idTerr = uuidv4();
    await pool.query(
        "INSERT INTO Terrain (idTerr, categorie, largeur, longueur,idb) VALUES (?, ?, ?, ?, ?)",
        [idTerr, categorie, largeur, longueur,idB]
    );
    console.log("bien insérer dans la table Terrain", idTerr,idB);
  }
    // Retour d'informations supplémentaires
    res.send({ message: "Annonce ajoutée avec succès.", idann});
  } catch (error) {
    console.error("Erreur lors de l'ajout de l'annonce :", error);
    res.send({ message: "Une erreur s'est produite lors de l'ajout de l'annonce." });
  }
});


// modifier une annonce
app.put("/api/v1/modifie/annonce/:id", auth, async (req, res) => {
  try {
    const id = req.params.id;
    const userId = req.userData.userId;

    const { titre, description, date_ajout } = req.body;


    await pool.query(

    "UPDATE annonce SET titre = ?, description = ?, date_ajout = ?, iduser = ? WHERE idann = ?",
      [titre, description, date_ajout, userId, id],
      (err, result) => {
        if (err) {
          console.error(err);
          return res.json({ error: "Une erreur s'est produite lors de la modification de l'annonce." });
        }
        if (result.affectedRows === 0) {
          return res.status(404).json({ error: "Aucune annonce trouvée avec l'identifiant spécifié." });
        }
        res.json({ message: "Annonce modifiée avec succès." });
      }

    );
  } catch (error) {
    console.log(error);
    res.json({ error: "Une erreur s'est produite lors de la modification de l'annonce." });
  }
});


// modifier annonce avec les image 
app.put("/api/v1/modifier/annonce/:id", auth, upload.array('file', 5), async (req, res) => {
  const userId = req.userData.userId;
  try {
    const id = req.params.id;
    const { titre, description, date_ajout } = req.body;

    let image1, image2, image3, image4, image5;

    if (req.files && req.files.length > 0) {
      image1 = req.files[0] ? req.files[0].filename : null;
      image2 = req.files[1] ? req.files[1].filename : null;
      image3 = req.files[2] ? req.files[2].filename : null;
      image4 = req.files[3] ? req.files[3].filename : null;
      image5 = req.files[4] ? req.files[4].filename : null;
    }

    await pool.query(
      "UPDATE annonce SET titre = ?, description = ?, date_ajout = ?, iduser = ?, image1 = ?, image2 = ?, image3 = ?, image4 = ?, image5 = ? WHERE idann = ?",
      [titre, description, date_ajout, userId, image1, image2, image3, image4, image5, id],
      (err, result) => {
        if (err) {
          console.error(err);
          return res.json({ error: "Une erreur s'est produite lors de la modification de l'annonce." });
        }
        if (result.affectedRows === 0) {
          return res.status(404).json({ error: "Aucune annonce trouvée avec l'identifiant spécifié." });
        }
        res.json({ message: "Annonce modifiée avec succès." });
      }
    );
  } catch (error) {
    console.log(error);
    res.json({ error: "Une erreur s'est produite lors de la modification de l'annonce." });
  }
});


// supprimer annonce et mettre le idann dans le bien null  
app.delete("/api/v1/delete/annonce/:id", auth, async (req, res) => {
  try {
    const id1 = req.params.id;
    const userId = req.userData.userId;

    // Suppression de l'annonce de la table "annonce"
    await pool.query(
      "DELETE FROM annonce WHERE idann = ? AND iduser = ?",
      [id1, userId],
      (error, result) => {
        if (error) {
          console.error(error);
          return res.status(500).json({ error: "Internal Server Error" });
        }

        if (result.affectedRows === 0) {
          return res.status(403).json({ error: "You are not authorized to delete this listing or the listing does not exist." });
        }

        // Suppression des liens entre l'annonce et les enregistrements dans la table "bien"
        pool.query(
          "UPDATE bien SET idann = NULL WHERE idann = ?",
          [id1],
          (error, result) => {
            if (error) {
              console.error(error);
            }
          }
        );

        // Récupération des images supprimées (si nécessaire)
        const deletedImages = {
          image1: result.image1,
          image2: result.image2,
          image3: result.image3,
          image4: result.image4,
          image5: result.image5
        };
        const responseJSON = {
          message: "Annonce deleted successfully",
          deletedImages: deletedImages
        };
        res.json(responseJSON);
      }
    );
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});


// recuperere tous les annonces 
app.get("/api/v1/all/annonce", (req, res) => {
  try {
    pool.query(
      "SELECT idann, titre, description, date_ajout, image1, image2, image3, image4, image5, iduser FROM annonce ORDER BY idann",
      (error, result) => {
        if (error) {
      return res.status(500).json({ message: "Erreur lors de la récupération des annonces." });
        }
        console.log("A ce niveau, il n'y a pas d'erreur");
        res.json({
          totalListing:result.length,
          listing: result
        });
      }
    );
  } catch (error) {
    console.error(error);
  }
});


// recuperer une annonce avec sans id join la tbale bien et clien 

app.get("/api/v1/single/annonces/:id", async (request, response) => {
  try {
    const annid = request.params.id;
    await pool.query(
     " SELECT annonce.idann, annonce.titre, annonce.description, annonce.date_ajout, annonce.image1, annonce.image2, annonce.image3, annonce.image4, annonce.image5, annonce.iduser, client.nom, client.prenom,client.num, client.email, bien.idB, bien.type AS bien_type, bien.surface AS bien_surface, bien.prix AS bien_prix,bien.ville AS bien_ville,bien.adresse AS bien_adresse, bien.userId AS bien_userId, bien.idann AS bien_idann FROM annonce INNER JOIN client ON annonce.iduser = client.iduser INNER JOIN bien ON annonce.idann = bien.idann WHERE annonce.idann = ?",

      [annid],
      (err, result) => {
        if (err) {
          console.error(err);
          return response.json({ error: "Une erreur s'est produite lors de la récupération des détails de l'annonce." });
        }
        if (result.length === 0) {
          return response.json({ error: "Aucune annonce trouvée avec l'identifiant spécifié." });
        }
        response.json(result[0]);
      }
    );
  } catch (error) {
    console.error(error);
    response.status(500).json({ error: "Une erreur s'est produite lors de la récupération des détails de l'annonce." });
  }
});

// recuperer une annonce avec id specifique et on inclu les info de le client 
app.get("/api/v1/single/whithinfoclient/annonces/:id", async (request, response) => {
  try {
    const annid = request.params.id;
    await pool.query(
      "SELECT annonce.idann, annonce.titre, annonce.description, annonce.date_ajout, annonce.image1, annonce.image2, annonce.image3, annonce.image4, annonce.image5, annonce.iduser, client.nom, client.prenom,client.num, client.email FROM annonce INNER JOIN client ON annonce.iduser = client.iduser WHERE annonce.idann = ?",
      [annid],
      (err, result) => {
        if (err) {
          console.error(err);
          return response.json({ error: "Une erreur s'est produite lors de la récupération des détails de l'annonce." });
        }
        if (result.length === 0) {
          return response.json({ error: "Aucune annonce trouvée avec l'identifiant spécifié." });
        }
        response.json(result[0]);
      }
    );
  } catch (error) {
    console.error(error);
    response.json({ error: "Une erreur s'est produite lors de la récupération des détails de l'annonce." });
  }
});


// Définition de la fonction removeNullValues à l'extérieur de la route
function removeNullValues(obj) {
  const newObj = {};
  for (const key in obj) {
    if (obj[key] !== null) {
      newObj[key] = obj[key];
    }
  }
  return newObj;
}
// recuperer jusqua le type de bien 
app.get("/api/v1/info/annonce/:id", async (request, response) => {
  try {
    const annid = request.params.id;
    await pool.query(
      ` SELECT  CONCAT(',', 
        CASE 
          WHEN bien.type = 'Terrain' THEN CONCAT(terrain.categorie, ',', terrain.largeur, ',', terrain.longueur,',', terrain.meuble) 
          WHEN bien.type = 'Industriel' THEN CONCAT( industriel.puissance, ',', industriel.puissance, ',', industriel.materiel, ',', industriel.taille, ',', industriel.meuble) 
          WHEN bien.type = 'Résidentiel' THEN CONCAT(résidentiel.meuble, ',', résidentiel.équipement, ',', résidentiel.type_residence) 
        WHEN bien.type = 'Commercial' THEN CONCAT(commercial.equipement, ',', commercial.etage, ',', commercial.meuble) 
          ELSE '' 
        END) AS selected_data, 
        annonce.titre, 
        annonce.description, 
        annonce.date_ajout, 
        annonce.image1, 
        annonce.image2, 
        annonce.image3, 
        annonce.image4, 
        annonce.image5, 
        annonce.iduser, 
        bien.idB, 
        bien.type, 
        bien.surface, 
        bien.prix, 
        bien.ville,
        bien.adresse,
        bien.userId, 
        bien.idann,
        résidentiel.meuble AS résidentiel_meuble,
        résidentiel.équipement AS résidentiel_équipement,
        résidentiel.type_residence AS résidentiel_residence,
        commercial.equipement AS commercial_equipement,
        commercial.etage AS commercial_etage,
        commercial.meuble AS commercial_meuble,
        industriel.capacite AS industriel_capacite,
        industriel.puissance AS industriel_puissance,
        industriel.materiel AS industriel_materiel,
        industriel.taille  AS industriel_taille,
        industriel.meuble AS industriel_meuble,
        terrain.categorie AS terrain_categorie,
        terrain.largeur AS terrain_largeur,
        terrain.longueur AS terrain_longueur,
        terrain.meuble AS terrain_meuble

      FROM bien 
      INNER JOIN annonce ON bien.idann = annonce.idann 
      LEFT JOIN terrain ON bien.idB = terrain.idb 
      LEFT JOIN industriel ON bien.idB = industriel.idb 
      LEFT JOIN résidentiel ON bien.idB = résidentiel.idb 
      LEFT JOIN commercial ON bien.idB = commercial.idb 
      WHERE annonce.idann = ?`,
      [annid],
      (err, result) => {
        if (err) {
          console.error(err);
          return response.json({ error: "Une erreur s'est produite lors de la récupération des détails de l'annonce." });
        }
        if (result.length === 0) {
          return response.json({ error: "Aucune annonce trouvée avec l'identifiant spécifié." });
        }
        // Renvoyer les données
        const formattedData = {
          titre: result[0].titre,
          description: result[0].description,
          date_ajout: result[0].date_ajout,
          image1: result[0].image1,
          image2: result[0].image2,
          image3: result[0].image3,
          image4: result[0].image4,
          image5: result[0].image5,
          iduser: result[0].iduser,
          idB: result[0].idB,
          type: result[0].type,
          surface: result[0].surface,
          prix: result[0].prix,
          ville:result[0].ville,
          adresse:result[0].adresse,
          userId: result[0].userId,
          idann: result[0].idann,
          bien_details: {}
        };
        

        if (result[0].type === 'Terrain') {
          formattedData.bien_details.terrain = removeNullValues({
            categorie: result[0].terrain_categorie,
            largeur: result[0].terrain_largeur,
            longueur: result[0].terrain_longueur,
            meuble: result[0].terrain_meuble,
          });
        } else if (result[0].type === 'Industriel') {
          formattedData.bien_details.industriel = removeNullValues({
            capacite:result[0].industriel_capacite,
            puissance: result[0].industriel_puissance,
            materiel: result[0].industriel_materiel,
            taille: result[0].industriel_taille,
            meuble: result[0].industriel_meuble,
          });
        } else if (result[0].type === 'Résidentiel') {
          formattedData.bien_details.résidentiel = removeNullValues({
            meuble: result[0].résidentiel_meuble,
            équipement: result[0].résidentiel_équipement,
            type_residence: result[0].résidentiel_residence

          });
        } else if (result[0].type === 'Commercial') {
          formattedData.bien_details.commercial = removeNullValues({
            equipement: result[0].commercial_equipement,
            etage: result[0].commercial_etage,
            meuble:result[0].commercial_meuble,

          });
        }
        
        response.json(formattedData);
        
      }
    );
  } catch (error) {
    console.error(error);
    response.json({ error: "Une erreur s'est produite lors de la récupération des détails de l'annonce." });
  }
});



// recuperer jusq le type de resedese (mais,app,st,villa) ---- tyi mzl tina ville et adresse g bien
app.get("/api/v1/info/pro/annonce/:id", async (request, response) => {
  try {
    const annid = request.params.id;
    await pool.query(
      ` SELECT CONCAT(',',
      CASE
      WHEN bien.type = 'Terrain' THEN CONCAT(terrain.categorie, ',', terrain.largeur, ',', terrain.longueur)
      WHEN bien.type = 'Industriel' THEN CONCAT(industriel.puissance, ',', industriel.materiel, ',', industriel.taille)
      WHEN bien.type = 'Résidentiel' AND résidentiel.type_residence = 'Maison' THEN CONCAT(maison.etage_maison, ',', résidentiel.meuble, ',', résidentiel.équipement, ',', résidentiel.type_residence)
      WHEN bien.type = 'Résidentiel' AND résidentiel.type_residence = 'Villa' THEN CONCAT(villa.etage_villa, ',', villa.type_villa, ',', résidentiel.meuble, ',', résidentiel.équipement,',', résidentiel.type_residence)
      WHEN bien.type = 'Résidentiel' AND résidentiel.type_residence = 'Studio' THEN CONCAT(studio.idStu, ',', résidentiel.meuble, ',',  résidentiel.équipement, ',', résidentiel.type_residence)    
      WHEN bien.type = 'Résidentiel' AND résidentiel.type_residence = 'Appartement' THEN CONCAT(appartement.type_appartement, ',', résidentiel.meuble, ',', résidentiel.équipement, ',',  résidentiel.type_residence)    
      WHEN bien.type = 'Commercial' THEN CONCAT(commercial.equipement, ',', commercial.etage)
        ELSE ''
      END) AS selected_data,
      annonce.titre, 
      annonce.description, 
      annonce.date_ajout, 
      annonce.image1, 
      annonce.image2, 
      annonce.image3, 
      annonce.image4, 
      annonce.image5, 
      annonce.iduser, 
      bien.idB, 
      bien.type, 
      bien.surface, 
      bien.prix, 
      bien.userId, 
      bien.idann,
      bien.ville,
      bien.adresse,
      résidentiel.meuble AS résidentiel_meuble,

      résidentiel.équipement AS résidentiel_équipement,
   
      résidentiel.type_residence AS résidentiel_residence,
      commercial.equipement AS commercial_equipement,
      commercial.etage AS commercial_etage,
 
      commercial.meuble AS commercial_meuble,
   
      industriel.capacite AS industriel_capacite,
      industriel.puissance AS industriel_puissance,
      industriel.materiel AS industriel_materiel,
      industriel.taille  AS industriel_taille,
      
      industriel.meuble AS industriel_meuble,
  
      terrain.categorie AS terrain_categorie,
      terrain.largeur AS terrain_largeur,
      terrain.longueur AS terrain_longueur,

      terrain.meuble AS terrain_meuble,
   
      maison.etage_maison AS maison_etage,
      villa.etage_villa AS villa_etage,
      villa.type_villa AS villa_type,
     appartement.type_appartement AS appartement_type
    FROM bien
    INNER JOIN annonce ON bien.idann = annonce.idann
    LEFT JOIN terrain ON bien.idB = terrain.idb
    LEFT JOIN industriel ON bien.idB = industriel.idb
    LEFT JOIN résidentiel ON bien.idB = résidentiel.idb
    LEFT JOIN commercial ON bien.idB = commercial.idb
    LEFT JOIN maison ON maison.idres = résidentiel.idres
    LEFT JOIN villa ON villa.idres = résidentiel.idres
    LEFT JOIN studio ON studio.idres = résidentiel.idres
    LEFT JOIN appartement ON appartement.idres = résidentiel.idres
    WHERE annonce.idann = ? `,
      [annid],
      (err, result) => {
        if (err) {
          console.error(err);
          return response.json({ error: "Une erreur s'est produite lors de la récupération des détails de l'annonce." });
        }
        if (result.length === 0) {
          return response.json({ error: "Aucune annonce trouvée avec l'identifiant spécifié." });
        }
        // Renvoyer les données
        const formattedData = {
          titre: result[0].titre,
          description: result[0].description,
          date_ajout: result[0].date_ajout,
          image1: result[0].image1,
          image2: result[0].image2,
          image3: result[0].image3,
          image4: result[0].image4,
          image5: result[0].image5,
          iduser: result[0].iduser,
          idB: result[0].idB,
          type: result[0].type,
          surface: result[0].surface,
          prix: result[0].prix,
          userId: result[0].userId,
          idann: result[0].idann,
          adresse:result[0].adresse,
          ville:result[0].ville,
          bien_details: {}
        };

        if (result[0].type === 'Terrain') {
          formattedData.bien_details.terrain = removeNullValues({
            categorie: result[0].terrain_categorie,
            largeur: result[0].terrain_largeur,
            longueur: result[0].terrain_longueur,
       
            meuble: result[0].terrain_meuble
         
          });
         } 
  else if (result[0].type === 'Industriel') {
          formattedData.bien_details.industriel = removeNullValues({
            capacite: result[0].industriel_capacite,
            puissance: result[0].industriel_puissance,
            materiel: result[0].industriel_materiel,
            taille: result[0].industriel_taille,
    
            meuble: result[0].industriel_meuble
      
          });
          } 
 else if (result[0].type === 'Résidentiel'&& result[0].résidentiel_residence === 'Villa') {
          formattedData.bien_details.résidentiel = removeNullValues({
            meuble: result[0].résidentiel_meuble,
        
            équipement: result[0].résidentiel_équipement,
       
            type_residence: result[0].résidentiel_residence,
            etage_villa: result[0].villa_etage,
            type_villa: result[0].villa_type
          });
          }
        
else if (result[0].type === 'Résidentiel' && result[0].résidentiel_residence ==='Appartement'){
          formattedData.bien_details.résidentiel = removeNullValues({
            meuble: result[0].résidentiel_meuble,
  
            équipement: result[0].résidentiel_équipement,
           
            type_residence: result[0].résidentiel_residence,
            type_appartement: result[0].appartement_type

          });
          }
 else if (result[0].type === 'Résidentiel' && result[0].résidentiel_residence ==='Maison'){
          formattedData.bien_details.résidentiel = removeNullValues({
            meuble: result[0].résidentiel_meuble,
      
            équipement: result[0].résidentiel_équipement,
    
            type_residence: result[0].résidentiel_residence,
            type_appartement: result[0].appartement_type,
            etage_maison: result[0].maison_etage

          });
           } 
 else if (result[0].type === 'Résidentiel' && result[0].résidentiel_residence ==='Stodio'){
          formattedData.bien_details.résidentiel = removeNullValues({
            meuble: result[0].résidentiel_meuble,
        
            équipement: result[0].résidentiel_équipement,
 
            type_residence: result[0].résidentiel_residence,
            type_appartement: result[0].appartement_type,
            etage_maison: result[0].maison_etage

          });
          } 
 else if (result[0].type === 'Commercial') {
          formattedData.bien_details.commercial = removeNullValues({
            equipement: result[0].commercial_equipement,
            etage: result[0].commercial_etage,
       
            meuble: result[0].commercial_meuble
     
          });
          }
        response.json(formattedData);
      }
    );
  } catch (error) {
    console.error(error);
    response.json({ error: "Une erreur s'est produite lors de la récupération des détails de l'annonce." });
  }
});



 //section recement ajouter , recuperere les dernier annonce ajouter.

app.get("/api/v1/recement/annonces", (req, res) => {
  try {
    pool.query(

      " SELECT annonce.idann, annonce.titre, description,image1, image2, image3, image4, image5, iduser, ville, adresse, prix FROM annonce LEFT JOIN bien ON bien.idann = annonce.idann",
      (error, result) => {
        if (error) {
          console.log(error);
          res.json({ error: "Une erreur s'est produite lors de la récupération des annonces." });
          return;
        }
        
        // Triez les annonces par ID 1 2 3 4 5 
        result.sort((a, b) => b.idann - a.idann);
        // dayi labghit 3 4 lsl atan 12 aka
        const dixDernieresAnnonces = result.slice(0, 3);
        res.json({ annonces: dixDernieresAnnonces });
      }
    );
  } catch (error) {
    console.log(error);
    res.json({ error: "Une erreur s'est produite lors de la récupération des annonces." });
  }
});



app.get("/api/v1/basiquee/recherche", (req, res) => {
    const { ville, prix } = req.query; 
    if (!ville || !prix) {
        return res.json({ error: "Veuillez fournir une ville et un prix." });
    }
    pool.query(
        "SELECT \
            CASE \
                WHEN bien.type = 'Terrain' THEN JSON_OBJECT('categorie', terrain.categorie, 'largeur', terrain.largeur, 'longueur', terrain.longueur) \
                WHEN bien.type = 'Industriel' THEN JSON_OBJECT('puissance', industriel.puissance, 'materiel', industriel.materiel, 'taille', industriel.taille) \
                WHEN bien.type = 'Résidentiel' AND résidentiel.type_residence = 'Maison' THEN JSON_OBJECT('etage_maison', maison.etage_maison, 'meuble', résidentiel.meuble, 'équipement', résidentiel.équipement, 'type_residence', résidentiel.type_residence) \
                WHEN bien.type = 'Résidentiel' AND résidentiel.type_residence = 'Villa' THEN JSON_OBJECT('etage_villa', villa.etage_villa, 'type_villa', villa.type_villa, 'meuble', résidentiel.meuble, 'équipement', résidentiel.équipement, 'type_residence', résidentiel.type_residence) \
                WHEN bien.type = 'Résidentiel' AND résidentiel.type_residence = 'Studio' THEN JSON_OBJECT('idStu', studio.idStu, 'meuble', résidentiel.meuble, 'équipement', résidentiel.équipement, 'type_residence', résidentiel.type_residence) \
                WHEN bien.type = 'Résidentiel' AND résidentiel.type_residence = 'Appartement' THEN JSON_OBJECT('type_appartement', appartement.type_appartement, 'meuble', résidentiel.meuble, 'équipement', résidentiel.équipement, 'type_residence', résidentiel.type_residence) \
                WHEN bien.type = 'Commercial' THEN JSON_OBJECT('equipement', commercial.equipement, 'etage', commercial.etage) \
                ELSE JSON_OBJECT() \
            END AS selected_data, \
            annonce.titre, \
            annonce.description, \
            annonce.date_ajout, \
            annonce.image1, \
            annonce.image2, \
            annonce.image3, \
            annonce.image4, \
            annonce.image5, \
            annonce.iduser, \
            bien.idB, \
            bien.type, \
            bien.surface, \
            bien.prix, \
            bien.userId, \
            bien.idann, \
            bien.ville, \
            bien.adresse \
        FROM bien \
        INNER JOIN annonce ON bien.idann = annonce.idann \
        LEFT JOIN terrain ON bien.idB = terrain.idb \
        LEFT JOIN industriel ON bien.idB = industriel.idb \
        LEFT JOIN résidentiel ON bien.idB = résidentiel.idb \
        LEFT JOIN commercial ON bien.idB = commercial.idb \
        LEFT JOIN maison ON maison.idres = résidentiel.idres \
        LEFT JOIN villa ON villa.idres = résidentiel.idres \
        LEFT JOIN studio ON studio.idres = résidentiel.idres \
        LEFT JOIN appartement ON appartement.idres = résidentiel.idres \
        WHERE bien.ville = ? AND bien.prix <= ?",
        [ville, prix],
        (error, result) => {
            if (error) {
                console.error(error);
                return res.json({ error: "Une erreur s'est produite lors de la recherche." });
            } else {
                // Convertir la chaîne JSON en objet JavaScript
                result.forEach(item => {
                    item.selected_data = JSON.parse(item.selected_data);
                });
                const response = {
                    totalListing: result.length,
                    listing: result
                };
                res.json(response);
            }
        }
    );
});


// recherche avancé 
app.get("/api/v1/avance/recherche", (req, res) => {

  const { ville, meuble, surface, type, prix } = req.query;

  pool.query(
   " SELECT annonce.idann, annonce.titre, annonce.description, annonce.date_ajout, annonce.image1, annonce.image2, annonce.image3, annonce.image4, annonce.image5, bien.type, bien.prix, bien.surface, annonce.iduser FROM annonce JOIN bien ON bien.idann = annonce.idann LEFT JOIN résidentiel ON résidentiel.idb = bien.idB LEFT JOIN industriel ON industriel.idb = bien.idB LEFT JOIN commercial ON commercial.idb = bien.idB LEFT JOIN terrain ON terrain.idb = bien.idB WHERE ((résidentiel.meuble = ? OR résidentiel.meuble IS NULL) OR (industriel.meuble = ? OR industriel.meuble IS NULL) OR (commercial.meuble = ? OR commercial.meuble IS NULL) OR (terrain.meuble = ? OR terrain.meuble IS NULL)) AND bien.surface = ? AND bien.ville = ? AND bien.type = ? AND bien.prix <= ? ",
    [meuble,meuble,meuble,meuble, surface, ville, type, prix],
    (error, result) => {
      if (error) {
        console.error(error);
        res.send("Une erreur s'est produite lors de la recherche.");
      } else {
        res.send({
          totalListing: result.length,
          listing: result
        });
      }
    }
  );
});


app.get("/api/v1/info/pr/annonce", async (request, response) => {
  try {
    await pool.query(
      `SELECT
        CASE
          WHEN bien.type = 'Terrain' THEN JSON_OBJECT('categorie', terrain.categorie, 'largeur', terrain.largeur, 'longueur', terrain.longueur)
          WHEN bien.type = 'Industriel' THEN JSON_OBJECT('puissance', industriel.puissance, 'materiel', industriel.materiel, 'taille', industriel.taille)
          WHEN bien.type = 'Résidentiel' AND résidentiel.type_residence = 'Maison' THEN JSON_OBJECT('etage_maison', maison.etage_maison, 'meuble', résidentiel.meuble, 'équipement', résidentiel.équipement, 'type_residence', résidentiel.type_residence)
          WHEN bien.type = 'Résidentiel' AND résidentiel.type_residence = 'Villa' THEN JSON_OBJECT('etage_villa', villa.etage_villa, 'type_villa', villa.type_villa, 'meuble', résidentiel.meuble, 'équipement', résidentiel.équipement, 'type_residence', résidentiel.type_residence)
          WHEN bien.type = 'Résidentiel' AND résidentiel.type_residence = 'Studio' THEN JSON_OBJECT('idStu', studio.idStu, 'meuble', résidentiel.meuble, 'équipement', résidentiel.équipement, 'type_residence', résidentiel.type_residence)
          WHEN bien.type = 'Résidentiel' AND résidentiel.type_residence = 'Appartement' THEN JSON_OBJECT('type_appartement', appartement.type_appartement, 'meuble', résidentiel.meuble, 'équipement', résidentiel.équipement, 'type_residence', résidentiel.type_residence)
          WHEN bien.type = 'Commercial' THEN JSON_OBJECT('equipement', commercial.equipement, 'etage', commercial.etage)
          ELSE JSON_OBJECT()
        END AS selected_data,
        annonce.titre, 
        annonce.description, 
        annonce.date_ajout, 
        annonce.image1, 
        annonce.image2, 
        annonce.image3, 
        annonce.image4, 
        annonce.image5, 
        annonce.iduser, 
        bien.idB, 
        bien.type, 
        bien.surface, 
        bien.prix, 
        bien.userId, 
        bien.idann,
        bien.ville,
        bien.adresse
      FROM bien
      INNER JOIN annonce ON bien.idann = annonce.idann
      LEFT JOIN terrain ON bien.idB = terrain.idb
      LEFT JOIN industriel ON bien.idB = industriel.idb
      LEFT JOIN résidentiel ON bien.idB = résidentiel.idb
      LEFT JOIN commercial ON bien.idB = commercial.idb
      LEFT JOIN maison ON maison.idres = résidentiel.idres
      LEFT JOIN villa ON villa.idres = résidentiel.idres
      LEFT JOIN studio ON studio.idres = résidentiel.idres
      LEFT JOIN appartement ON appartement.idres = résidentiel.idres`,
      (err, result) => {
        if (err) {
          console.error(err);
          return response.json({ error: "Une erreur s'est produite lors de la récupération des détails de l'annonce." });
        }
        if (result.length === 0) {
          return response.json({ error: "Aucune annonce trouvée avec l'identifiant spécifié." });
        }
      
        result.forEach(row => {
          if (row.selected_data) {
            row.selected_data = JSON.parse(row.selected_data);
          }
        });

        response.json(result);
      }
    );
  } catch (error) {
    console.error(error);
    response.json({ error: "Une erreur s'est produite lors de la récupération des détails de l'annonce." });
  }
});



































app.listen(3000,()=>{
console.log("I am listen what kho ")
})




















