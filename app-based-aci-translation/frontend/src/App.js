import './App.css';
import React, { useState } from 'react';
import axios from 'axios';
import styled from 'styled-components';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import CircularProgress from '@mui/material/CircularProgress';
import Typography from '@mui/material/Typography';

const FormContainer = styled.form`
  display: flex;
  align-items: center;
  width: 300px;
  flex-flow: column;
  height: auto;
  margin: 0 auto;
  border: 2px solid #1E90FF;
  border-radius: 20px;
  background: white;
  transform: translate(0, 50%);

  h2 {
    font-family: Arial, Helvetica, sans-serif;
    font-size: 16px;
  }

  message {
    margin: 0;
  }

  button {
    background: #1E90FF;
    color: #fff;
    padding: 10px;
    margin: 5px;
    width: 150px;
    border: none;
    border-radius: 10px;
    box-sizing: border-box;
    margin-top: 10px;
  }

  button:disabled,
  button[disabled]{
    border-radius: 10px;
    background-color: #ccc;
    box-sizing: border-box;
    color: #fff;
  }

  label {
    font-weight: light;
    font-size: 14px;
    margin-bottom: 5px;
    margin-top: 10px;
  }

  input {
    padding: 5px;
    border: 1px solid #ccc;
    border-radius: 4px;
  }
`;

const InfoIcon = styled.span`
  position: relative;
  display: inline-block;
  width: 15px;
  height: 15px;
  border-radius: 50%;
  background-color: #1E90FF;
  color: #fff;
  font-size: 12px;
  text-align: center;
  cursor: pointer;
`;

const InfoIconSmall = styled.span`
  position: relative;
  display: inline-block;
  width: 12px;
  height: 12px;
  border-radius: 50%;
  background-color: #1E90FF;
  color: #fff;
  font-size: 10px;
  text-align: center;
  cursor: pointer;
`;

const InfoIconContent = styled.span`
  content: ok;
  visibility: hidden;
  width: 120px;
  background-color: #1E90FF;
  color: #fff;
  font-weight: bold;
  font-size: 12px;
  text-align: center;
  border-radius: 4px;
  padding: 5px;
  position: absolute;
  z-index: 1;
  bottom: 125%;
  left: 50%;
  transform: translateX(-50%);
  opacity: 0;
  transition: opacity 0.3s ease;
`;

const InfoIconWrapper = styled.div`
  position: relative;
  display: inline-block;

  &:hover ${InfoIconContent} {
    visibility: visible;
    opacity: 1;
  }
`;

function App() {
  const [selectedFiles, setSelectedFiles] = useState([]);
  const [host, setHost] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [message, setMessage] = useState('');
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [showDownload, setShowDownload] = useState(false);
  const [tooltips, setTooltips] = useState([]);
  const [isChecked, setIsChecked] = useState(false);

  const areAllFieldsFilled = (selectedFiles) && (host !== "") && (username !== "") && (password !== "")

  const handleTooltipHover = (index, isVisible) => {
    setTooltips((prevTooltips) => {
      const updatedTooltips = [...prevTooltips];
      updatedTooltips[index] = isVisible;
      return updatedTooltips;
    });
  };

  const handleFileChange = (e) => {
    // get all files
    const files = Array.from(e.target.files);
    setSelectedFiles(files);
  };

  const handleRunCheckboxChange = (e) => {
    const { checked } = e.target;
    setIsChecked(checked);
  };

  const handleModifyClick = (e) => {
    e.preventDefault();
    if (selectedFiles.length > 0) {
      setOpen(true);
      setLoading(true);
    let formData = new FormData();
    selectedFiles.forEach((file, index) => {
      formData.append(`file${index + 1}`, file);
    });

    // Append other necessary data
    formData.append("host", host);
    formData.append("username", username);
    formData.append("password", password);
    formData.append("isChecked", isChecked);
    // const reader = new FileReader();
    // reader.onload = () => {
    //   const content = reader.result;
      
      try{
        // var playbook = ''
        // const parsedData = safeLoad(content);
        // playbook = JSON.stringify(parsedData)
        axios.post('http://127.0.0.1:5000/translate', formData, {
            headers: {
              'Content-Type': 'multipart/form-data',
              'Access-Control-Allow-Origin': '*',
            },
          })
          .then((response) => {
            console.log(response.data);
            setLoading(false);
            setMessage(String(response.data[0].message));
            if (response.data[1] === 200){
              setShowDownload(true);
            }
          })
          .catch((error) => {
            console.error(error);
            setLoading(false);
            setMessage(String(error));
          });
        } catch (error) {
          console.error(error);
          setLoading(false);
          setMessage('Translator was unable to parse the files. Please check the files.');
      }
      };
    };
    //   reader.readAsText(selectedFiles[i]);
    //   }
    // };

    const handleClose = () => {
      setOpen(false);
    };

    const handleDownload = (e) => {
      e.preventDefault();
        axios.get('http://127.0.0.1:5000/download-terraform-files', { responseType: 'blob' })
          .then((response) => {
            const url = window.URL.createObjectURL(new Blob([response.data]));
            const link = document.createElement('a');
            link.href = url;
            link.setAttribute('download', 'terraform_files.zip');
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        })
        .catch((error) => {
          console.error(error);
          setMessage(String(error));
        });
    };

  return (
    <div>
      <FormContainer>
      <h2>ACI Ansible to Terraform translator</h2>
      <InfoIconWrapper> 
      <InfoIcon onMouseEnter={() => handleTooltipHover(0, true)} onMouseLeave={() => handleTooltipHover(0, false)}>
          ?
        </InfoIcon>
        {tooltips[0] && <InfoIconContent>This application translates an ACI Ansible playbook to a Terraform configuration file and its corresponding state file. Please note that this is not a static translation! The selected playbook will be run by Ansible and interact with the provided APIC for the translation to complete.</InfoIconContent>}
      </InfoIconWrapper>
        <label>Choose your ACI Ansible playbook  <InfoIconWrapper> 
      <InfoIconSmall onMouseEnter={() => handleTooltipHover(1, true)} onMouseLeave={() => handleTooltipHover(1, false)}>
          ?
        </InfoIconSmall>
        {tooltips[1] && <InfoIconContent>Please choose an ACI Ansible playbook to translate it into a Terraform configuration file.</InfoIconContent>}
      </InfoIconWrapper></label>
        <input type="file" onChange={handleFileChange} multiple/>
      <label>Dry-Run<input type="checkbox" checked={isChecked} onChange={handleRunCheckboxChange}/><InfoIconWrapper>
      <InfoIconSmall onMouseEnter={() => handleTooltipHover(2, true)} onMouseLeave={() => handleTooltipHover(2, false)}>
          ?
        </InfoIconSmall>
        {tooltips[2] && <InfoIconContent>Please check this box if the selected playbook has already pushed configuration to the APIC during a previous run.</InfoIconContent>}
      </InfoIconWrapper></label>
        <label>APIC Host <InfoIconWrapper> 
      <InfoIconSmall onMouseEnter={() => handleTooltipHover(3, true)} onMouseLeave={() => handleTooltipHover(3, false)}>
          ?
        </InfoIconSmall>
        {tooltips[3] && <InfoIconContent>If Dry Run is checked, please provide the credentials of the APIC that has the configuration pushed by the selected playbook during a previous run.</InfoIconContent>}
      </InfoIconWrapper></label>
        <input type="text" name="host" value={host} onChange={(e) => setHost(e.target.value)} />
        <label>APIC User ID</label>
        <input type="text" name="user" value={username} onChange={(e) => setUsername(e.target.value)} />
        <label>APIC Password</label>
        <input type="password" name="password" value={password} onChange={(e) => setPassword(e.target.value)} />
        <button onClick={handleModifyClick} disabled={!areAllFieldsFilled}>Translate</button>
        { showDownload && (
                <button onClick={handleDownload}>Download Translated Files</button>
            )}
      </FormContainer>
        <Dialog open={open} onClose={handleClose}>
        <DialogContent>
          {loading ? (
            <div style={{ display: 'flex', alignItems: 'center' }}>
              <CircularProgress />
              <Typography variant="body1" style={{ marginLeft: 10 }}>
                Translating...
              </Typography>
            </div>
          ) : (
            <p>{message}</p>
          )}
        </DialogContent>
        {!loading && (
        <DialogActions>
          <Button onClick={handleClose} color="primary">
            Close
          </Button>
        </DialogActions>
        )}
      </Dialog>
    </div>
  );
  };

export default App;
